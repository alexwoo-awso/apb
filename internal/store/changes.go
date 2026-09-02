package store

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/alexwoo-awso/apb/internal/model"
)

// metaFloorKey records the highest changelog sequence that has been pruned.
// A router whose cursor sits below it has provably missed changes and must
// perform a full resynchronisation.
const metaFloorKey = "_changes_floor"

func emitChange(ctx context.Context, t *sql.Tx, op, ip string, family int, at int64) error {
	_, err := t.ExecContext(ctx,
		`INSERT INTO changes(op, ip, family, at) VALUES(?, ?, ?, ?)`, op, ip, family, at)
	return err
}

func bumpMetrics(ctx context.Context, t *sql.Tx, now int64, deviceID int64, reports, additions, removals int) error {
	if reports == 0 && additions == 0 && removals == 0 {
		return nil
	}
	hour := now - now%3600
	upsert := `INSERT INTO metrics_hourly(hour, device_id, reports, additions, removals)
	           VALUES(?, ?, ?, ?, ?)
	           ON CONFLICT(hour, device_id) DO UPDATE SET
	             reports = reports + excluded.reports,
	             additions = additions + excluded.additions,
	             removals = removals + excluded.removals`
	if _, err := t.ExecContext(ctx, upsert, hour, 0, reports, additions, removals); err != nil {
		return err
	}
	if deviceID != 0 {
		if _, err := t.ExecContext(ctx, upsert, hour, deviceID, reports, additions, removals); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) metaGet(ctx context.Context, key string) int64 {
	var v string
	if err := db.ro.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func (db *DB) metaSet(ctx context.Context, key string, val int64) error {
	_, err := db.rw.ExecContext(ctx,
		`INSERT INTO settings(key, value, updated_at) VALUES(?, ?, 0)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, strconv.FormatInt(val, 10))
	return err
}

// Cursor returns the latest changelog sequence. It survives pruning because
// SQLite keeps the AUTOINCREMENT high-water mark in sqlite_sequence.
func (db *DB) Cursor(ctx context.Context) (int64, error) {
	var c int64
	err := db.ro.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT MAX(seq) FROM changes),
		                 (SELECT seq FROM sqlite_sequence WHERE name = 'changes'), 0)`).Scan(&c)
	return c, err
}

// CursorFloor is the lowest sequence a router may still resume from.
func (db *DB) CursorFloor(ctx context.Context) int64 { return db.metaGet(ctx, metaFloorKey) }

// SetCursorFloor is called by the retention job after pruning history.
func (db *DB) SetCursorFloor(ctx context.Context, seq int64) error {
	if seq <= db.CursorFloor(ctx) {
		return nil
	}
	return db.metaSet(ctx, metaFloorKey, seq)
}

// Delta is one increment of the replication stream.
type Delta struct {
	Cursor  int64 // sequence the router should store once applied
	Adds    []string
	Removes []string
	More    bool // further changes are already waiting; poll again immediately
	Resync  bool // the router's cursor is too old, it must run a full sync
}

// Empty reports whether there is nothing for the router to do.
func (d Delta) Empty() bool { return len(d.Adds) == 0 && len(d.Removes) == 0 && !d.Resync }

// ChangesSince builds the delta a router should apply, capped at maxBytes of
// address text so the response always fits inside a RouterOS fetch buffer.
//
// Within one delta the same address can appear more than once (added, then
// removed). Only the final operation is emitted, which is both correct and
// smaller on the wire.
func (db *DB) ChangesSince(ctx context.Context, cursor int64, maxBytes int) (Delta, error) {
	var d Delta
	latest, err := db.Cursor(ctx)
	if err != nil {
		return d, err
	}
	d.Cursor = cursor
	if cursor < db.CursorFloor(ctx) {
		d.Resync = true
		return d, nil
	}
	if cursor >= latest {
		d.Cursor = latest
		return d, nil
	}
	if maxBytes <= 0 {
		maxBytes = 8192
	}
	// Address text averages ~14 bytes; over-fetch a little then trim by budget.
	limit := maxBytes/8 + 16
	rows, err := db.ro.QueryContext(ctx,
		`SELECT seq, op, ip FROM changes WHERE seq > ? ORDER BY seq LIMIT ?`, cursor, limit)
	if err != nil {
		return d, err
	}
	defer rows.Close()

	type entry struct {
		op  string
		seq int64
	}
	final := map[string]entry{}
	order := make([]string, 0, limit)
	var used, lastSeq int64
	consumed := 0
	for rows.Next() {
		var seq int64
		var op, ip string
		if err := rows.Scan(&seq, &op, &ip); err != nil {
			return d, err
		}
		if _, seen := final[ip]; !seen {
			if used+int64(len(ip))+1 > int64(maxBytes) {
				d.More = true
				break
			}
			used += int64(len(ip)) + 1
			order = append(order, ip)
		}
		final[ip] = entry{op: op, seq: seq}
		lastSeq = seq
		consumed++
	}
	if err := rows.Err(); err != nil {
		return d, err
	}
	if lastSeq == 0 {
		d.Cursor = latest
		return d, nil
	}
	for _, ip := range order {
		if final[ip].op == model.OpAdd {
			d.Adds = append(d.Adds, ip)
		} else {
			d.Removes = append(d.Removes, ip)
		}
	}
	d.Cursor = lastSeq
	if lastSeq < latest {
		d.More = true
	}
	return d, nil
}

// SnapshotPage returns one page of the current blocklist for a full
// resynchronisation. Paging is by address id so a page is stable even while
// new addresses arrive.
func (db *DB) SnapshotPage(ctx context.Context, afterID int64, maxBytes int, ipv6 bool) (ips []string, nextID int64, more bool, err error) {
	if maxBytes <= 0 {
		maxBytes = 8192
	}
	q := `SELECT id, ip FROM addresses WHERE state = 'blocked' AND id > ?`
	if !ipv6 {
		q += ` AND family = 4`
	}
	q += ` ORDER BY id LIMIT ?`
	limit := maxBytes/8 + 16
	rows, err := db.ro.QueryContext(ctx, q, afterID, limit)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	var used int
	for rows.Next() {
		var id int64
		var ip string
		if err := rows.Scan(&id, &ip); err != nil {
			return nil, 0, false, err
		}
		if used+len(ip)+1 > maxBytes {
			more = true
			break
		}
		used += len(ip) + 1
		ips = append(ips, ip)
		nextID = id
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	if !more && len(ips) > 0 {
		// A page that exactly filled the row limit may have more behind it.
		var remaining int
		check := `SELECT COUNT(*) FROM (SELECT 1 FROM addresses WHERE state = 'blocked' AND id > ?`
		args := []any{nextID}
		if !ipv6 {
			check += ` AND family = 4`
		}
		check += ` LIMIT 1)`
		if err := db.ro.QueryRowContext(ctx, check, args...).Scan(&remaining); err != nil {
			return nil, 0, false, err
		}
		more = remaining > 0
	}
	return ips, nextID, more, nil
}

// BlockedCount is the number of addresses currently pushed to the routers.
func (db *DB) BlockedCount(ctx context.Context, ipv6 bool) (int64, error) {
	q := `SELECT COUNT(*) FROM addresses WHERE state = 'blocked'`
	if !ipv6 {
		q += ` AND family = 4`
	}
	var n int64
	err := db.ro.QueryRowContext(ctx, q).Scan(&n)
	return n, err
}

// RecentChanges powers the changelog view in the console.
func (db *DB) RecentChanges(ctx context.Context, limit int) ([]model.Change, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT seq, op, ip, family, at FROM changes ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Change
	for rows.Next() {
		var c model.Change
		if err := rows.Scan(&c.Seq, &c.Op, &c.IP, &c.Family, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
