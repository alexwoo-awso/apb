package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/rsc"
)

const deviceCols = `id, name, identity, description, ros_branch, ros_version, model, enabled,
	list_name, detect_list, block_timeout, verify_cert, sync_interval, report_interval, contribute, consume, ipv6,
	cursor, applied, last_sync_at, last_report_at, last_boot_at, last_ip, reports_total,
	tags, notes, created_at, created_by`

func scanDevice(s scanner) (model.Device, error) {
	var d model.Device
	err := s.Scan(&d.ID, &d.Name, &d.Identity, &d.Description, &d.ROSBranch, &d.ROSVersion, &d.Model,
		&d.Enabled, &d.ListName, &d.DetectList, &d.BlockTimeout, &d.VerifyCert, &d.SyncInterval, &d.ReportInterval,
		&d.Contribute, &d.Consume, &d.IPv6, &d.Cursor, &d.Applied, &d.LastSyncAt, &d.LastReportAt,
		&d.LastBootAt, &d.LastIP, &d.ReportsTotal, &d.Tags, &d.Notes, &d.CreatedAt, &d.CreatedBy)
	return d, err
}

// CreateDevice registers a router.
func (db *DB) CreateDevice(ctx context.Context, d model.Device) (model.Device, error) {
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" {
		return d, errors.New("device name is required")
	}
	s := db.Settings()
	if d.ListName == "" {
		d.ListName = s.DefaultListName
	}
	if d.DetectList == "" {
		d.DetectList = s.DefaultDetectList
	}
	if d.BlockTimeout == "" {
		d.BlockTimeout = defaultBlockTimeout(d.ROSBranch, s.DefaultBlockTimeout)
	}
	if d.VerifyCert == "" {
		d.VerifyCert = defaultVerify(d.ROSBranch)
	}
	if d.SyncInterval <= 0 {
		d.SyncInterval = s.DefaultSyncInterval
	}
	if d.ReportInterval <= 0 {
		d.ReportInterval = s.DefaultReportInterval
	}
	if d.ROSBranch != "v6" {
		d.ROSBranch = "v7"
	}
	d.CreatedAt = time.Now().Unix()

	r, err := db.rw.ExecContext(ctx,
		`INSERT INTO devices(name, identity, description, ros_branch, ros_version, model, enabled,
		    list_name, detect_list, block_timeout, verify_cert, sync_interval, report_interval, contribute, consume,
		    ipv6, tags, notes, created_at, created_by)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Name, d.Identity, d.Description, d.ROSBranch, d.ROSVersion, d.Model, boolInt(d.Enabled),
		d.ListName, d.DetectList, d.BlockTimeout, d.VerifyCert, d.SyncInterval, d.ReportInterval,
		boolInt(d.Contribute), boolInt(d.Consume), boolInt(d.IPv6), d.Tags, d.Notes, d.CreatedAt, d.CreatedBy)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return d, errors.New("a device with that name already exists")
		}
		return d, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return d, err
	}
	return db.DeviceByID(ctx, id)
}

// UpdateDevice saves the operator-editable fields.
func (db *DB) UpdateDevice(ctx context.Context, d model.Device) error {
	if d.ROSBranch != "v6" {
		d.ROSBranch = "v7"
	}
	_, err := db.rw.ExecContext(ctx,
		`UPDATE devices SET name = ?, description = ?, ros_branch = ?, enabled = ?, list_name = ?,
		    detect_list = ?, block_timeout = ?, verify_cert = ?, sync_interval = ?, report_interval = ?,
		    contribute = ?, consume = ?, ipv6 = ?, tags = ?, notes = ?
		 WHERE id = ?`,
		strings.TrimSpace(d.Name), d.Description, d.ROSBranch, boolInt(d.Enabled), d.ListName,
		d.DetectList, d.BlockTimeout, d.VerifyCert, d.SyncInterval, d.ReportInterval,
		boolInt(d.Contribute), boolInt(d.Consume), boolInt(d.IPv6), d.Tags, d.Notes, d.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("a device with that name already exists")
	}
	return err
}

// DeleteDevice removes a router and everything attributed to it. Addresses
// reported only by this device keep their history but lose a corroborator.
func (db *DB) DeleteDevice(ctx context.Context, id int64) error {
	return db.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id); err != nil {
			return err
		}
		_, err := t.ExecContext(ctx,
			`UPDATE addresses SET device_count = (SELECT COUNT(*) FROM reports WHERE address_id = addresses.id),
			     report_count = (SELECT COALESCE(SUM(count), 0) FROM reports WHERE address_id = addresses.id)
			 WHERE id IN (SELECT address_id FROM report_events WHERE device_id = ?)`, id)
		return err
	})
}

// DeviceByID fetches one router.
func (db *DB) DeviceByID(ctx context.Context, id int64) (model.Device, error) {
	row := db.ro.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// DeviceByName fetches one router by its unique name.
func (db *DB) DeviceByName(ctx context.Context, name string) (model.Device, error) {
	row := db.ro.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE name = ?`, name)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// ListDevices returns every registered router, newest first.
func (db *DB) ListDevices(ctx context.Context, query string) ([]model.Device, error) {
	where := ""
	var args []any
	if q := strings.TrimSpace(query); q != "" {
		where = ` WHERE name LIKE ? OR identity LIKE ? OR description LIKE ? OR tags LIKE ? OR last_ip LIKE ?`
		like := "%" + q + "%"
		args = append(args, like, like, like, like, like)
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT `+deviceCols+`, (SELECT COUNT(*) FROM device_tokens dt WHERE dt.device_id = devices.id AND dt.revoked_at = 0)
		 FROM devices`+where+` ORDER BY name COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		var d model.Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Identity, &d.Description, &d.ROSBranch, &d.ROSVersion,
			&d.Model, &d.Enabled, &d.ListName, &d.DetectList, &d.BlockTimeout, &d.VerifyCert, &d.SyncInterval,
			&d.ReportInterval, &d.Contribute, &d.Consume, &d.IPv6, &d.Cursor, &d.Applied,
			&d.LastSyncAt, &d.LastReportAt, &d.LastBootAt, &d.LastIP, &d.ReportsTotal,
			&d.Tags, &d.Notes, &d.CreatedAt, &d.CreatedBy, &d.TokenCount); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeviceByTokenHash resolves a bearer token to its device. It returns
// ErrNotFound for unknown, revoked or expired tokens so callers cannot
// distinguish the cases and leak information to a prober.
func (db *DB) DeviceByTokenHash(ctx context.Context, hash []byte) (model.Device, int64, error) {
	var (
		tokenID   int64
		expiresAt int64
		revokedAt int64
	)
	row := db.ro.QueryRowContext(ctx,
		`SELECT t.id, t.expires_at, t.revoked_at, `+prefixCols("d")+`
		 FROM device_tokens t JOIN devices d ON d.id = t.device_id WHERE t.hash = ?`, hash)
	var d model.Device
	err := row.Scan(&tokenID, &expiresAt, &revokedAt,
		&d.ID, &d.Name, &d.Identity, &d.Description, &d.ROSBranch, &d.ROSVersion, &d.Model,
		&d.Enabled, &d.ListName, &d.DetectList, &d.BlockTimeout, &d.VerifyCert, &d.SyncInterval, &d.ReportInterval,
		&d.Contribute, &d.Consume, &d.IPv6, &d.Cursor, &d.Applied, &d.LastSyncAt, &d.LastReportAt,
		&d.LastBootAt, &d.LastIP, &d.ReportsTotal, &d.Tags, &d.Notes, &d.CreatedAt, &d.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return d, 0, ErrNotFound
	} else if err != nil {
		return d, 0, err
	}
	now := time.Now().Unix()
	if revokedAt != 0 || (expiresAt != 0 && expiresAt <= now) || !d.Enabled {
		return model.Device{}, 0, ErrNotFound
	}
	return d, tokenID, nil
}

func prefixCols(alias string) string {
	parts := strings.Split(deviceCols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// TouchToken records a successful authentication. It is deliberately cheap and
// best-effort: a failure here must not fail the request.
func (db *DB) TouchToken(ctx context.Context, tokenID int64, now int64) {
	_, _ = db.rw.ExecContext(ctx,
		`UPDATE device_tokens SET last_used_at = ?, use_count = use_count + 1 WHERE id = ?`, now, tokenID)
}

// RecordSync stores the cursor a router acknowledged along with its liveness.
func (db *DB) RecordSync(ctx context.Context, deviceID, cursor, applied int64, ip string, now int64) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE devices SET cursor = ?, applied = CASE WHEN ? >= 0 THEN ? ELSE applied END,
		    last_sync_at = ?, last_ip = ? WHERE id = ?`,
		cursor, applied, applied, now, ip, deviceID)
	return err
}

// RecordSeen notes that a router made contact without claiming a cursor. A
// device rebuilding its list talks to the server every poll, and reporting it
// as never having synced while its requests are in the log is simply wrong.
func (db *DB) RecordSeen(ctx context.Context, deviceID int64, ip string, now int64) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE devices SET last_sync_at = ?, last_ip = CASE WHEN ? <> '' THEN ? ELSE last_ip END
		 WHERE id = ?`, now, ip, ip, deviceID)
	return err
}

// RecordIdentity stores what the router told us about itself.
func (db *DB) RecordIdentity(ctx context.Context, deviceID int64, identity, rosVersion, boardModel, ip string) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE devices SET
		    identity    = CASE WHEN ? <> '' THEN ? ELSE identity END,
		    ros_version = CASE WHEN ? <> '' THEN ? ELSE ros_version END,
		    model       = CASE WHEN ? <> '' THEN ? ELSE model END,
		    last_ip     = CASE WHEN ? <> '' THEN ? ELSE last_ip END
		 WHERE id = ?`,
		identity, identity, rosVersion, rosVersion, boardModel, boardModel, ip, ip, deviceID)
	return err
}

// RecordBootstrap notes that a router restarted its list from scratch.
func (db *DB) RecordBootstrap(ctx context.Context, deviceID, now int64) error {
	_, err := db.rw.ExecContext(ctx, `UPDATE devices SET last_boot_at = ? WHERE id = ?`, now, deviceID)
	return err
}

// ------------------------------------------------------------------- tokens

// CreateToken stores a new credential. The caller holds the only copy of the
// plaintext; the database keeps a keyed hash.
func (db *DB) CreateToken(ctx context.Context, deviceID int64, prefix string, hash []byte, label, actor string, expiresAt int64) (int64, error) {
	r, err := db.rw.ExecContext(ctx,
		`INSERT INTO device_tokens(device_id, label, prefix, hash, created_at, created_by, expires_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		deviceID, label, prefix, hash, time.Now().Unix(), actor, expiresAt)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// RevokeToken disables a credential immediately.
func (db *DB) RevokeToken(ctx context.Context, id int64) error {
	_, err := db.rw.ExecContext(ctx,
		`UPDATE device_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = 0`, time.Now().Unix(), id)
	return err
}

// ListTokens returns the credentials for a device, newest first.
func (db *DB) ListTokens(ctx context.Context, deviceID int64) ([]model.DeviceToken, error) {
	rows, err := db.ro.QueryContext(ctx,
		`SELECT id, device_id, label, prefix, created_at, created_by, expires_at, revoked_at, last_used_at, use_count
		 FROM device_tokens WHERE device_id = ? ORDER BY created_at DESC, id DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DeviceToken
	for rows.Next() {
		var t model.DeviceToken
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.Label, &t.Prefix, &t.CreatedAt, &t.CreatedBy,
			&t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.UseCount); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TokenByID fetches one credential record.
func (db *DB) TokenByID(ctx context.Context, id int64) (model.DeviceToken, error) {
	var t model.DeviceToken
	err := db.ro.QueryRowContext(ctx,
		`SELECT id, device_id, label, prefix, created_at, created_by, expires_at, revoked_at, last_used_at, use_count
		 FROM device_tokens WHERE id = ?`, id).
		Scan(&t.ID, &t.DeviceID, &t.Label, &t.Prefix, &t.CreatedAt, &t.CreatedBy,
			&t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.UseCount)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// defaultBlockTimeout gives a new device the longest entry timeout proven to
// work on its RouterOS branch. Both branches refuse a long timeout, and both
// refuse the entry rather than clamping it, so a router given too large a value
// holds nothing while reporting success.
//
// The configured default is only used when it is not longer than the branch
// allows: an operator who set a global default suited to RouterOS 7 must not
// silently break every RouterOS 6 device they add afterwards.
func defaultBlockTimeout(branch, configured string) string {
	best := rsc.DefaultBlockTimeout(branch)
	if configured == "" {
		return best
	}
	if rsc.TimeoutWithinBranch(branch, configured) {
		return configured
	}
	return best
}

// defaultVerify picks a sensible TLS verification mode per RouterOS branch.
// RouterOS 7 ships built-in trust anchors, so certificates can be validated
// out of the box. RouterOS 6 has no trust store until a CA is imported, and a
// default of "yes" there would simply stop every router from syncing, so it
// starts unvalidated and the console flags it.
func defaultVerify(branch string) string {
	if branch == "v6" {
		return "no"
	}
	return "yes-without-crl"
}
