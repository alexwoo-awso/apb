package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/netutil"
)

// IngestResult summarises what a batch of reported addresses did.
type IngestResult struct {
	Accepted     int   // rows that produced or refreshed a report
	NewAddresses int   // addresses never seen before
	Broadcast    int   // addresses that crossed the threshold and were queued for the routers
	Whitelisted  int   // rejected because a whitelist rule covers them
	Invalid      int   // unparseable or bogon
	Duplicates   int   // repeated within the same batch
	Cursor       int64 // changelog cursor after the batch
}

// Ingest records a batch of addresses reported by one device. The whole batch
// is a single transaction: either the router's report lands completely or not
// at all, so a retry can never leave half a batch behind.
func (db *DB) Ingest(ctx context.Context, deviceID int64, raw []string, now int64) (IngestResult, error) {
	var res IngestResult
	s := db.Settings()

	seen := make(map[string]struct{}, len(raw))
	addrs := make([]netip.Addr, 0, len(raw))
	for _, r := range raw {
		a, err := netutil.ParseBlockable(r)
		if err != nil {
			res.Invalid++
			continue
		}
		key := a.String()
		if _, dup := seen[key]; dup {
			res.Duplicates++
			continue
		}
		seen[key] = struct{}{}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		res.Cursor, _ = db.Cursor(ctx)
		return res, nil
	}

	var ttl int64
	if s.DefaultTTLDays > 0 {
		ttl = int64(s.DefaultTTLDays) * 86400
	}

	err := db.tx(ctx, func(t *sql.Tx) error {
		for _, a := range addrs {
			ok, err := db.ingestOne(ctx, t, deviceID, a, now, ttl, s, &res)
			if err != nil {
				return err
			}
			if ok {
				res.Accepted++
			}
		}
		if err := bumpMetrics(ctx, t, now, deviceID, res.Accepted, res.Broadcast, 0); err != nil {
			return err
		}
		if res.Accepted > 0 {
			if _, err := t.ExecContext(ctx,
				`UPDATE devices SET last_report_at = ?, reports_total = reports_total + ? WHERE id = ?`,
				now, res.Accepted, deviceID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	res.Cursor, _ = db.Cursor(ctx)
	return res, nil
}

func (db *DB) ingestOne(ctx context.Context, t *sql.Tx, deviceID int64, a netip.Addr,
	now, ttl int64, s Settings, res *IngestResult) (bool, error) {

	bin := netutil.Bin(a)
	ip := a.String()

	// A whitelist rule always wins, and the address is not even recorded.
	var wl int
	if err := t.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM whitelist WHERE net_start <= ? AND net_end >= ?`, bin, bin).Scan(&wl); err != nil {
		return false, err
	}
	if wl > 0 {
		res.Whitelisted++
		return false, nil
	}

	var (
		id      int64
		state   string
		fresh   bool
		expires int64
	)
	err := t.QueryRowContext(ctx, `SELECT id, state FROM addresses WHERE ip = ?`, ip).Scan(&id, &state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		fresh = true
		if ttl > 0 {
			expires = now + ttl
		}
		r, err := t.ExecContext(ctx,
			`INSERT INTO addresses(ip, ip_bin, family, state, first_seen, last_seen,
			    report_count, device_count, expires_at, source)
			 VALUES(?, ?, ?, 'released', ?, ?, 0, 0, ?, 'report')`,
			ip, bin, netutil.Family(a), now, now, expires)
		if err != nil {
			return false, err
		}
		if id, err = r.LastInsertId(); err != nil {
			return false, err
		}
		state = model.StateReleased
		res.NewAddresses++
	case err != nil:
		return false, err
	default:
		if ttl > 0 {
			expires = now + ttl
		}
		if _, err := t.ExecContext(ctx,
			`UPDATE addresses SET last_seen = ?, expires_at = ? WHERE id = ?`, now, expires, id); err != nil {
			return false, err
		}
	}

	if _, err := t.ExecContext(ctx,
		`INSERT INTO reports(address_id, device_id, first_at, last_at, count)
		 VALUES(?, ?, ?, ?, 1)
		 ON CONFLICT(address_id, device_id) DO UPDATE SET last_at = excluded.last_at, count = count + 1`,
		id, deviceID, now, now); err != nil {
		return false, err
	}

	var devCount, repCount int64
	if err := t.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(count), 0) FROM reports WHERE address_id = ?`, id).
		Scan(&devCount, &repCount); err != nil {
		return false, err
	}
	if _, err := t.ExecContext(ctx,
		`UPDATE addresses SET device_count = ?, report_count = ? WHERE id = ?`,
		devCount, repCount, id); err != nil {
		return false, err
	}

	if _, err := t.ExecContext(ctx,
		`INSERT INTO report_events(at, device_id, address_id, ip, fresh) VALUES(?, ?, ?, ?, ?)`,
		now, deviceID, id, ip, boolInt(fresh)); err != nil {
		return false, err
	}

	// Promote to blocked once the corroboration thresholds are met.
	if state != model.StateBlocked &&
		repCount >= int64(s.AutoBlockReports) && devCount >= int64(s.AutoBlockDevices) {
		if _, err := t.ExecContext(ctx,
			`UPDATE addresses SET state = 'blocked', blocked_at = ?, released_at = 0, release_reason = '' WHERE id = ?`,
			now, id); err != nil {
			return false, err
		}
		if err := emitChange(ctx, t, model.OpAdd, ip, netutil.Family(a), now); err != nil {
			return false, err
		}
		res.Broadcast++
	}
	return true, nil
}

// BlockManual adds or re-blocks a single address on an operator's authority.
func (db *DB) BlockManual(ctx context.Context, raw, actor, notes string, expiresAt int64) (model.Address, error) {
	a, err := netutil.ParseBlockable(raw)
	if err != nil {
		return model.Address{}, err
	}
	now := time.Now().Unix()
	bin := netutil.Bin(a)
	ip := a.String()

	err = db.tx(ctx, func(t *sql.Tx) error {
		var wl string
		errW := t.QueryRowContext(ctx,
			`SELECT cidr FROM whitelist WHERE net_start <= ? AND net_end >= ? LIMIT 1`, bin, bin).Scan(&wl)
		if errW == nil {
			return fmt.Errorf("%s is covered by whitelist entry %s; remove that rule first", ip, wl)
		} else if !errors.Is(errW, sql.ErrNoRows) {
			return errW
		}

		var id int64
		var state string
		e := t.QueryRowContext(ctx, `SELECT id, state FROM addresses WHERE ip = ?`, ip).Scan(&id, &state)
		if errors.Is(e, sql.ErrNoRows) {
			r, err := t.ExecContext(ctx,
				`INSERT INTO addresses(ip, ip_bin, family, state, first_seen, last_seen, expires_at,
				     source, notes, created_by, blocked_at)
				 VALUES(?, ?, ?, 'blocked', ?, ?, ?, 'manual', ?, ?, ?)`,
				ip, bin, netutil.Family(a), now, now, expiresAt, notes, actor, now)
			if err != nil {
				return err
			}
			id, _ = r.LastInsertId()
			state = model.StateReleased
		} else if e != nil {
			return e
		} else {
			if _, err := t.ExecContext(ctx,
				`UPDATE addresses SET state = 'blocked', last_seen = ?, blocked_at = ?, expires_at = ?,
				    released_at = 0, release_reason = '', notes = CASE WHEN ? = '' THEN notes ELSE ? END
				 WHERE id = ?`,
				now, now, expiresAt, notes, notes, id); err != nil {
				return err
			}
		}
		if state != model.StateBlocked {
			if err := emitChange(ctx, t, model.OpAdd, ip, netutil.Family(a), now); err != nil {
				return err
			}
			return bumpMetrics(ctx, t, now, 0, 0, 1, 0)
		}
		return nil
	})
	if err != nil {
		return model.Address{}, err
	}
	return db.AddressByIP(ctx, ip)
}

// Release marks addresses as no longer blocked and tells every router to drop
// them. The rows stay for their history; use Delete to forget them entirely.
func (db *DB) Release(ctx context.Context, ids []int64, reason string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	now := time.Now().Unix()
	n := 0
	err := db.tx(ctx, func(t *sql.Tx) error {
		for _, id := range ids {
			var ip, state string
			var family int
			err := t.QueryRowContext(ctx, `SELECT ip, family, state FROM addresses WHERE id = ?`, id).
				Scan(&ip, &family, &state)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return err
			}
			if _, err := t.ExecContext(ctx,
				`UPDATE addresses SET state = 'released', released_at = ?, release_reason = ?, expires_at = 0 WHERE id = ?`,
				now, reason, id); err != nil {
				return err
			}
			if state == model.StateBlocked {
				if err := emitChange(ctx, t, model.OpRemove, ip, family, now); err != nil {
					return err
				}
				n++
			}
		}
		return bumpMetrics(ctx, t, now, 0, 0, 0, n)
	})
	return n, err
}

// Delete removes addresses outright, after telling the routers to drop them.
func (db *DB) Delete(ctx context.Context, ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	now := time.Now().Unix()
	n := 0
	err := db.tx(ctx, func(t *sql.Tx) error {
		for _, id := range ids {
			var ip, state string
			var family int
			err := t.QueryRowContext(ctx, `SELECT ip, family, state FROM addresses WHERE id = ?`, id).
				Scan(&ip, &family, &state)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return err
			}
			if state == model.StateBlocked {
				if err := emitChange(ctx, t, model.OpRemove, ip, family, now); err != nil {
					return err
				}
			}
			if _, err := t.ExecContext(ctx, `DELETE FROM report_events WHERE address_id = ?`, id); err != nil {
				return err
			}
			if _, err := t.ExecContext(ctx, `DELETE FROM addresses WHERE id = ?`, id); err != nil {
				return err
			}
			n++
		}
		return bumpMetrics(ctx, t, now, 0, 0, 0, n)
	})
	return n, err
}

// Reblock puts released addresses back on the list.
func (db *DB) Reblock(ctx context.Context, ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	now := time.Now().Unix()
	n := 0
	err := db.tx(ctx, func(t *sql.Tx) error {
		for _, id := range ids {
			var ip, state string
			var family int
			var bin []byte
			err := t.QueryRowContext(ctx, `SELECT ip, family, state, ip_bin FROM addresses WHERE id = ?`, id).
				Scan(&ip, &family, &state, &bin)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return err
			}
			if state == model.StateBlocked {
				continue
			}
			var wl int
			if err := t.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM whitelist WHERE net_start <= ? AND net_end >= ?`, bin, bin).Scan(&wl); err != nil {
				return err
			}
			if wl > 0 {
				continue
			}
			if _, err := t.ExecContext(ctx,
				`UPDATE addresses SET state = 'blocked', blocked_at = ?, released_at = 0, release_reason = '' WHERE id = ?`,
				now, id); err != nil {
				return err
			}
			if err := emitChange(ctx, t, model.OpAdd, ip, family, now); err != nil {
				return err
			}
			n++
		}
		return bumpMetrics(ctx, t, now, 0, n, 0, 0)
	})
	return n, err
}

// SetExpiry adjusts the server-side lifetime of the given addresses.
func (db *DB) SetExpiry(ctx context.Context, ids []int64, expiresAt int64) error {
	if len(ids) == 0 {
		return nil
	}
	return db.tx(ctx, func(t *sql.Tx) error {
		for _, id := range ids {
			if _, err := t.ExecContext(ctx, `UPDATE addresses SET expires_at = ? WHERE id = ?`, expiresAt, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// ExpireAddresses releases blocked addresses whose lifetime has run out.
func (db *DB) ExpireAddresses(ctx context.Context, now int64) (int, error) {
	rows, err := db.ro.QueryContext(ctx,
		`SELECT id FROM addresses WHERE state = 'blocked' AND expires_at > 0 AND expires_at <= ? LIMIT 5000`, now)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return db.Release(ctx, ids, "expired")
}

// ---------------------------------------------------------------- queries

// AddressFilter describes a blocklist query.
type AddressFilter struct {
	Query    string // free text: substring of the IP, country code, ASN org
	State    string // blocked | released | "" for both
	Country  string
	ASN      int64
	Family   int
	MinHits  int64
	MinPeers int64
	Since    int64 // last_seen >= Since
	Sort     string
	Limit    int
	Offset   int
}

func (f AddressFilter) where() (string, []any) {
	var cond []string
	var args []any
	if f.State != "" {
		cond = append(cond, "state = ?")
		args = append(args, f.State)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		if p, err := netutil.ParsePrefix(q); err == nil && !p.One {
			cond = append(cond, "(ip_bin BETWEEN ? AND ?)")
			args = append(args, p.Start, p.End)
		} else {
			like := "%" + q + "%"
			cond = append(cond, "(ip LIKE ? OR country LIKE ? OR country_name LIKE ? OR asn_org LIKE ? OR notes LIKE ?)")
			args = append(args, like, like, like, like, like)
		}
	}
	if f.Country != "" {
		cond = append(cond, "country = ?")
		args = append(args, strings.ToUpper(f.Country))
	}
	if f.ASN > 0 {
		cond = append(cond, "asn = ?")
		args = append(args, f.ASN)
	}
	if f.Family == 4 || f.Family == 6 {
		cond = append(cond, "family = ?")
		args = append(args, f.Family)
	}
	if f.MinHits > 0 {
		cond = append(cond, "report_count >= ?")
		args = append(args, f.MinHits)
	}
	if f.MinPeers > 0 {
		cond = append(cond, "device_count >= ?")
		args = append(args, f.MinPeers)
	}
	if f.Since > 0 {
		cond = append(cond, "last_seen >= ?")
		args = append(args, f.Since)
	}
	if len(cond) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(cond, " AND "), args
}

var addressSorts = map[string]string{
	"recent":  "last_seen DESC, id DESC",
	"oldest":  "first_seen ASC, id ASC",
	"first":   "first_seen DESC, id DESC",
	"reports": "report_count DESC, last_seen DESC",
	"peers":   "device_count DESC, report_count DESC",
	"ip":      "ip_bin ASC",
	"country": "country ASC, report_count DESC",
}

const addressCols = `id, ip, family, state, first_seen, last_seen, report_count, device_count,
	expires_at, country, country_name, continent, asn, asn_org, geo_at, source, notes,
	created_by, blocked_at, released_at, release_reason`

// ListAddresses runs a filtered, paged blocklist query and also reports the
// total number of matching rows so the UI can paginate.
func (db *DB) ListAddresses(ctx context.Context, f AddressFilter) ([]model.Address, int64, error) {
	where, args := f.where()

	var total int64
	if err := db.ro.QueryRowContext(ctx, `SELECT COUNT(*) FROM addresses`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	order, ok := addressSorts[f.Sort]
	if !ok {
		order = addressSorts["recent"]
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	q := `SELECT ` + addressCols + ` FROM addresses` + where + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	rows, err := db.ro.QueryContext(ctx, q, append(append([]any{}, args...), limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.Address
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanAddress(s scanner) (model.Address, error) {
	var a model.Address
	err := s.Scan(&a.ID, &a.IP, &a.Family, &a.State, &a.FirstSeen, &a.LastSeen,
		&a.ReportCount, &a.DeviceCount, &a.ExpiresAt, &a.Country, &a.CountryName,
		&a.Continent, &a.ASN, &a.ASNOrg, &a.GeoAt, &a.Source, &a.Notes,
		&a.CreatedBy, &a.BlockedAt, &a.ReleasedAt, &a.ReleaseReason)
	return a, err
}

// AddressByID looks up one address.
func (db *DB) AddressByID(ctx context.Context, id int64) (model.Address, error) {
	row := db.ro.QueryRowContext(ctx, `SELECT `+addressCols+` FROM addresses WHERE id = ?`, id)
	a, err := scanAddress(row)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// AddressByIP looks up one address by its canonical text form.
func (db *DB) AddressByIP(ctx context.Context, ip string) (model.Address, error) {
	row := db.ro.QueryRowContext(ctx, `SELECT `+addressCols+` FROM addresses WHERE ip = ?`, ip)
	a, err := scanAddress(row)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// ReportsFor returns the per-device sighting record for one address, which is
// what answers "how many routers saw this, and when did each first see it".
func (db *DB) ReportsFor(ctx context.Context, addressID int64) ([]model.Report, error) {
	rows, err := db.ro.QueryContext(ctx,
		`SELECT r.address_id, r.device_id, COALESCE(d.name, '(deleted)'), r.first_at, r.last_at, r.count
		 FROM reports r LEFT JOIN devices d ON d.id = r.device_id
		 WHERE r.address_id = ? ORDER BY r.first_at ASC`, addressID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Report
	for rows.Next() {
		var r model.Report
		if err := rows.Scan(&r.AddressID, &r.DeviceID, &r.DeviceName, &r.FirstAt, &r.LastAt, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetNotes updates the operator note on an address.
func (db *DB) SetNotes(ctx context.Context, id int64, notes string) error {
	_, err := db.rw.ExecContext(ctx, `UPDATE addresses SET notes = ? WHERE id = ?`, notes, id)
	return err
}

// IDsForFilter resolves a filter to the matching address ids, for bulk
// actions taken from the UI ("apply to all matching rows").
func (db *DB) IDsForFilter(ctx context.Context, f AddressFilter, cap int) ([]int64, error) {
	where, args := f.where()
	if cap <= 0 || cap > 100000 {
		cap = 100000
	}
	rows, err := db.ro.QueryContext(ctx, `SELECT id FROM addresses`+where+` LIMIT ?`,
		append(append([]any{}, args...), cap)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
