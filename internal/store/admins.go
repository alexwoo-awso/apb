package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

const adminCols = `id, username, display_name, email, pass_hash, role, totp_secret, totp_enrolled,
	disabled, must_change_password, failed_attempts, locked_until, created_at, created_by,
	last_login_at, last_login_ip`

func scanAdmin(s scanner) (model.Admin, error) {
	var a model.Admin
	var secret []byte
	err := s.Scan(&a.ID, &a.Username, &a.DisplayName, &a.Email, &a.PassHash, &a.Role, &secret,
		&a.TOTPEnrolled, &a.Disabled, &a.MustChangePassword, &a.FailedAttempts, &a.LockedUntil,
		&a.CreatedAt, &a.CreatedBy, &a.LastLoginAt, &a.LastLoginIP)
	a.TOTPSecret = secret
	return a, err
}

// CreateAdmin adds a console account.
func (db *DB) CreateAdmin(ctx context.Context, a model.Admin) (model.Admin, error) {
	a.Username = strings.TrimSpace(a.Username)
	if a.Username == "" {
		return a, errors.New("username is required")
	}
	if a.Role == "" {
		a.Role = model.RoleAdmin
	}
	a.CreatedAt = time.Now().Unix()
	r, err := db.rw.ExecContext(ctx,
		`INSERT INTO admins(username, display_name, email, pass_hash, role, disabled,
		     must_change_password, created_at, created_by)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Username, a.DisplayName, a.Email, a.PassHash, a.Role, boolInt(a.Disabled),
		boolInt(a.MustChangePassword), a.CreatedAt, a.CreatedBy)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return a, errors.New("that username is already taken")
		}
		return a, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return a, err
	}
	return db.AdminByID(ctx, id)
}

// AdminByID fetches one account.
func (db *DB) AdminByID(ctx context.Context, id int64) (model.Admin, error) {
	a, err := scanAdmin(db.ro.QueryRowContext(ctx, `SELECT `+adminCols+` FROM admins WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// AdminByUsername fetches one account by login name (case-insensitive).
func (db *DB) AdminByUsername(ctx context.Context, name string) (model.Admin, error) {
	a, err := scanAdmin(db.ro.QueryRowContext(ctx, `SELECT `+adminCols+` FROM admins WHERE username = ?`, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// ListAdmins returns every account.
func (db *DB) ListAdmins(ctx context.Context) ([]model.Admin, error) {
	rows, err := db.ro.QueryContext(ctx, `SELECT `+adminCols+` FROM admins ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountAdmins reports how many accounts exist, used to detect first run.
func (db *DB) CountAdmins(ctx context.Context) (int64, error) {
	var n int64
	err := db.ro.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

// CountOwners reports how many enabled owners remain, so the last one cannot
// be deleted or demoted.
func (db *DB) CountOwners(ctx context.Context) (int64, error) {
	var n int64
	err := db.ro.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM admins WHERE role = 'owner' AND disabled = 0`).Scan(&n)
	return n, err
}

// UpdateAdminProfile saves the editable fields of an account.
func (db *DB) UpdateAdminProfile(ctx context.Context, id int64, display, email, role string, disabled bool) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE admins SET display_name = ?, email = ?, role = ?, disabled = ? WHERE id = ?`,
		display, email, role, boolInt(disabled), id)
	return err
}

// SetPassword stores a new password hash and clears the change requirement.
func (db *DB) SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE admins SET pass_hash = ?, must_change_password = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?`,
		hash, boolInt(mustChange), id)
	return err
}

// SetTOTP stores a sealed TOTP secret. Passing nil clears the enrolment.
func (db *DB) SetTOTP(ctx context.Context, id int64, sealed []byte, enrolled bool) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE admins SET totp_secret = ?, totp_enrolled = ? WHERE id = ?`, sealed, boolInt(enrolled), id)
	return err
}

// NoteLoginFailure increments the failure counter and locks the account once
// the configured threshold is reached.
func (db *DB) NoteLoginFailure(ctx context.Context, id int64) error {
	s := db.Settings()
	lockUntil := time.Now().Add(time.Duration(s.LoginLockMinutes) * time.Minute).Unix()
	_, err := db.rw.ExecContext(ctx,
		`UPDATE admins SET failed_attempts = failed_attempts + 1,
		    locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END
		 WHERE id = ?`, s.LoginMaxAttempts, lockUntil, id)
	return err
}

// NoteLoginSuccess clears the failure state and records the login.
func (db *DB) NoteLoginSuccess(ctx context.Context, id int64, ip string) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE admins SET failed_attempts = 0, locked_until = 0, last_login_at = ?, last_login_ip = ? WHERE id = ?`,
		time.Now().Unix(), ip, id)
	return err
}

// UnlockAdmin clears a lockout without touching the password.
func (db *DB) UnlockAdmin(ctx context.Context, id int64) error {
	_, err := db.rw.ExecContext(ctx, `UPDATE admins SET failed_attempts = 0, locked_until = 0 WHERE id = ?`, id)
	return err
}

// DeleteAdmin removes an account and every session it holds.
func (db *DB) DeleteAdmin(ctx context.Context, id int64) error {
	_, err := db.rw.ExecContext(ctx, `DELETE FROM admins WHERE id = ?`, id)
	return err
}

// ------------------------------------------------------------------ ui hints

// HintsSeen returns the set of explainer cards this admin has dismissed.
func (db *DB) HintsSeen(ctx context.Context, adminID int64) (map[string]bool, error) {
	rows, err := db.ro.QueryContext(ctx, `SELECT hint FROM ui_hints WHERE admin_id = ?`, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out[h] = true
	}
	return out, rows.Err()
}

// MarkHintSeen dismisses one explainer card for one admin.
func (db *DB) MarkHintSeen(ctx context.Context, adminID int64, hint string) error {
	_, err := db.rw.ExecContext(ctx,
		`INSERT INTO ui_hints(admin_id, hint, seen_at) VALUES(?, ?, ?)
		 ON CONFLICT(admin_id, hint) DO NOTHING`, adminID, hint, time.Now().Unix())
	return err
}

// ResetHints brings every explainer card back for one admin.
func (db *DB) ResetHints(ctx context.Context, adminID int64) error {
	_, err := db.rw.ExecContext(ctx, `DELETE FROM ui_hints WHERE admin_id = ?`, adminID)
	return err
}
