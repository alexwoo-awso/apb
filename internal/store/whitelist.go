package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/netutil"
)

// WhitelistPreview reports what adding a rule would do before it is added:
// which currently blocked addresses it releases, and how many in total.
type WhitelistPreview struct {
	CIDR    string
	Family  int
	Total   int64
	Samples []model.Address
}

// PreviewWhitelist resolves the effect of a prospective whitelist rule.
func (db *DB) PreviewWhitelist(ctx context.Context, raw string) (WhitelistPreview, error) {
	p, err := netutil.ParsePrefix(raw)
	if err != nil {
		return WhitelistPreview{}, err
	}
	out := WhitelistPreview{CIDR: p.CIDR, Family: p.Family}
	if err := db.ro.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM addresses WHERE state = 'blocked' AND ip_bin BETWEEN ? AND ?`,
		p.Start, p.End).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT `+addressCols+` FROM addresses WHERE state = 'blocked' AND ip_bin BETWEEN ? AND ?
		 ORDER BY report_count DESC LIMIT 25`, p.Start, p.End)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return out, err
		}
		out.Samples = append(out.Samples, a)
	}
	return out, rows.Err()
}

// AddWhitelist inserts a rule and immediately releases everything it covers,
// so the removal reaches the routers on their next poll.
func (db *DB) AddWhitelist(ctx context.Context, raw, reason, actor string, expiresAt int64) (model.WhitelistEntry, int, error) {
	p, err := netutil.ParsePrefix(raw)
	if err != nil {
		return model.WhitelistEntry{}, 0, err
	}
	now := time.Now().Unix()
	var released int
	var id int64

	err = db.tx(ctx, func(t *sql.Tx) error {
		r, err := t.ExecContext(ctx,
			`INSERT INTO whitelist(cidr, net_start, net_end, prefix_len, family, reason, expires_at, created_at, created_by)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(cidr) DO UPDATE SET reason = excluded.reason, expires_at = excluded.expires_at`,
			p.CIDR, p.Start, p.End, p.Bits, p.Family, reason, expiresAt, now, actor)
		if err != nil {
			return err
		}
		if id, err = r.LastInsertId(); err != nil {
			return err
		}

		rows, err := t.QueryContext(ctx,
			`SELECT id, ip, family FROM addresses WHERE state = 'blocked' AND ip_bin BETWEEN ? AND ?`,
			p.Start, p.End)
		if err != nil {
			return err
		}
		type victim struct {
			id     int64
			ip     string
			family int
		}
		var victims []victim
		for rows.Next() {
			var v victim
			if err := rows.Scan(&v.id, &v.ip, &v.family); err != nil {
				rows.Close()
				return err
			}
			victims = append(victims, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, v := range victims {
			if _, err := t.ExecContext(ctx,
				`UPDATE addresses SET state = 'released', released_at = ?, release_reason = ?, expires_at = 0 WHERE id = ?`,
				now, "whitelisted by "+p.CIDR, v.id); err != nil {
				return err
			}
			if err := emitChange(ctx, t, model.OpRemove, v.ip, v.family, now); err != nil {
				return err
			}
			released++
		}
		if released > 0 {
			if _, err := t.ExecContext(ctx, `UPDATE whitelist SET hits = hits + ? WHERE cidr = ?`, released, p.CIDR); err != nil {
				return err
			}
		}
		return bumpMetrics(ctx, t, now, 0, 0, 0, released)
	})
	if err != nil {
		return model.WhitelistEntry{}, 0, err
	}
	e, err := db.WhitelistByID(ctx, id)
	return e, released, err
}

// RemoveWhitelist deletes a rule. Addresses it released stay released until
// they are reported again or an operator re-blocks them.
func (db *DB) RemoveWhitelist(ctx context.Context, id int64) (string, error) {
	var cidr string
	err := db.rw.QueryRowContext(ctx, `SELECT cidr FROM whitelist WHERE id = ?`, id).Scan(&cidr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	_, err = db.rw.ExecContext(ctx, `DELETE FROM whitelist WHERE id = ?`, id)
	return cidr, err
}

// ExpireWhitelist drops rules whose lifetime has run out.
func (db *DB) ExpireWhitelist(ctx context.Context, now int64) (int, error) {
	r, err := db.rw.ExecContext(ctx, `DELETE FROM whitelist WHERE expires_at > 0 AND expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return int(n), nil
}

const whitelistCols = `id, cidr, prefix_len, family, reason, expires_at, created_at, created_by, hits`

// WhitelistByID fetches one rule.
func (db *DB) WhitelistByID(ctx context.Context, id int64) (model.WhitelistEntry, error) {
	var e model.WhitelistEntry
	err := db.ro.QueryRowContext(ctx, `SELECT `+whitelistCols+` FROM whitelist WHERE id = ?`, id).
		Scan(&e.ID, &e.CIDR, &e.PrefixLen, &e.Family, &e.Reason, &e.ExpiresAt, &e.CreatedAt, &e.CreatedBy, &e.Hits)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// ListWhitelist returns the rules, optionally filtered by a free text query.
func (db *DB) ListWhitelist(ctx context.Context, query string, limit, offset int) ([]model.WhitelistEntry, int64, error) {
	where := ""
	var args []any
	if q := strings.TrimSpace(query); q != "" {
		where = ` WHERE cidr LIKE ? OR reason LIKE ? OR created_by LIKE ?`
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	var total int64
	if err := db.ro.QueryRowContext(ctx, `SELECT COUNT(*) FROM whitelist`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT `+whitelistCols+` FROM whitelist`+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.WhitelistEntry
	for rows.Next() {
		var e model.WhitelistEntry
		if err := rows.Scan(&e.ID, &e.CIDR, &e.PrefixLen, &e.Family, &e.Reason,
			&e.ExpiresAt, &e.CreatedAt, &e.CreatedBy, &e.Hits); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// WhitelistCount is used by the dashboard.
func (db *DB) WhitelistCount(ctx context.Context) (int64, error) {
	var n int64
	err := db.ro.QueryRowContext(ctx, `SELECT COUNT(*) FROM whitelist`).Scan(&n)
	return n, err
}

// SeedWhitelist installs the operator's own networks on first run. It is a
// no-op for rules that already exist.
func (db *DB) SeedWhitelist(ctx context.Context, cidrs []string, reason string) error {
	for _, c := range cidrs {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if _, _, err := db.AddWhitelist(ctx, c, reason, "system", 0); err != nil {
			return fmt.Errorf("seed whitelist %s: %w", c, err)
		}
	}
	return nil
}
