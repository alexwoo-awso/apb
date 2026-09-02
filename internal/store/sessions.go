package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

// CreateSession stores a session keyed by the hash of the cookie value.
func (db *DB) CreateSession(ctx context.Context, s model.Session) error {
	_, err := db.rw.ExecContext(ctx,
		`INSERT INTO sessions(id, admin_id, csrf, pending_totp, created_at, last_seen_at, expires_at, ip, user_agent)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.AdminID, s.CSRF, boolInt(s.PendingTOTP), s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.IP, s.UserAgent)
	return err
}

// Session loads a session by its hashed id, enforcing both the absolute and
// the idle deadline.
func (db *DB) Session(ctx context.Context, id []byte, idleSeconds int64) (model.Session, error) {
	var s model.Session
	err := db.ro.QueryRowContext(ctx,
		`SELECT id, admin_id, csrf, pending_totp, created_at, last_seen_at, expires_at, ip, user_agent
		 FROM sessions WHERE id = ?`, id).
		Scan(&s.ID, &s.AdminID, &s.CSRF, &s.PendingTOTP, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.IP, &s.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	} else if err != nil {
		return s, err
	}
	now := time.Now().Unix()
	if s.ExpiresAt <= now || (idleSeconds > 0 && now-s.LastSeenAt > idleSeconds) {
		_ = db.DeleteSession(ctx, id)
		return model.Session{}, ErrNotFound
	}
	return s, nil
}

// TouchSession refreshes the idle deadline. Writes are throttled to once a
// minute so an active console does not generate a write per request.
func (db *DB) TouchSession(ctx context.Context, id []byte, now int64) {
	_, _ = db.rw.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at < ?`, now, id, now-60)
}

// PromoteSession marks a half-authenticated session as fully signed in once
// the second factor has been verified.
func (db *DB) PromoteSession(ctx context.Context, id []byte) error {
	_, err := db.rw.ExecContext(ctx, `UPDATE sessions SET pending_totp = 0 WHERE id = ?`, id)
	return err
}

// DeleteSession signs one session out.
func (db *DB) DeleteSession(ctx context.Context, id []byte) error {
	_, err := db.rw.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionsForAdmin signs an account out everywhere. Used on password
// change, role change and account disable.
func (db *DB) DeleteSessionsForAdmin(ctx context.Context, adminID int64) error {
	_, err := db.rw.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id = ?`, adminID)
	return err
}

// SessionsForAdmin lists the active sessions of an account.
func (db *DB) SessionsForAdmin(ctx context.Context, adminID int64) ([]model.Session, error) {
	rows, err := db.ro.QueryContext(ctx,
		`SELECT id, admin_id, csrf, pending_totp, created_at, last_seen_at, expires_at, ip, user_agent
		 FROM sessions WHERE admin_id = ? ORDER BY last_seen_at DESC`, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Session
	for rows.Next() {
		var s model.Session
		if err := rows.Scan(&s.ID, &s.AdminID, &s.CSRF, &s.PendingTOTP, &s.CreatedAt,
			&s.LastSeenAt, &s.ExpiresAt, &s.IP, &s.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
