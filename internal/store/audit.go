package store

import (
	"context"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

// Audit appends an entry to the administrative log. It never returns an error
// to the caller: losing a request because the log is unavailable would be a
// worse outcome than a gap in the log, which the caller cannot fix anyway.
func (db *DB) Audit(ctx context.Context, e model.AuditEntry) {
	if e.At == 0 {
		e.At = time.Now().Unix()
	}
	if e.ActorType == "" {
		e.ActorType = "system"
	}
	_, _ = db.rw.ExecContext(ctx,
		`INSERT INTO audit_log(at, actor, actor_type, action, target, detail, ip, ok)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At, e.Actor, e.ActorType, e.Action, e.Target, e.Detail, e.IP, boolInt(e.OK))
}

// ListAudit returns the log, newest first, optionally filtered.
func (db *DB) ListAudit(ctx context.Context, query string, limit, offset int) ([]model.AuditEntry, int64, error) {
	where := ""
	var args []any
	if q := strings.TrimSpace(query); q != "" {
		where = ` WHERE actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?`
		like := "%" + q + "%"
		args = append(args, like, like, like, like, like)
	}
	var total int64
	if err := db.ro.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT id, at, actor, actor_type, action, target, detail, ip, ok FROM audit_log`+where+
			` ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`,
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.ActorType, &e.Action, &e.Target,
			&e.Detail, &e.IP, &e.OK); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
