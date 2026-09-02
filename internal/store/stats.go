package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

// Dashboard assembles the landing page in a handful of indexed queries.
func (db *DB) Dashboard(ctx context.Context, hours int) (model.Dashboard, error) {
	var d model.Dashboard
	now := time.Now().Unix()
	dayAgo := now - 86400
	weekAgo := now - 7*86400

	scalar := func(q string, args ...any) (int64, error) {
		var n int64
		err := db.ro.QueryRowContext(ctx, q, args...).Scan(&n)
		return n, err
	}
	var err error
	if d.Blocked, err = scalar(`SELECT COUNT(*) FROM addresses WHERE state = 'blocked'`); err != nil {
		return d, err
	}
	if d.Whitelisted, err = scalar(`SELECT COUNT(*) FROM whitelist`); err != nil {
		return d, err
	}
	if d.AddedDay, err = scalar(`SELECT COUNT(*) FROM changes WHERE op = 'A' AND at >= ?`, dayAgo); err != nil {
		return d, err
	}
	if d.RemovedDay, err = scalar(`SELECT COUNT(*) FROM changes WHERE op = 'R' AND at >= ?`, dayAgo); err != nil {
		return d, err
	}
	if d.AddedWeek, err = scalar(`SELECT COUNT(*) FROM changes WHERE op = 'A' AND at >= ?`, weekAgo); err != nil {
		return d, err
	}
	if d.ReportsDay, err = scalar(`SELECT COUNT(*) FROM report_events WHERE at >= ?`, dayAgo); err != nil {
		return d, err
	}
	if d.MultiDevice, err = scalar(`SELECT COUNT(*) FROM addresses WHERE state = 'blocked' AND device_count > 1`); err != nil {
		return d, err
	}
	if d.Devices, err = scalar(`SELECT COUNT(*) FROM devices`); err != nil {
		return d, err
	}
	if d.Cursor, err = db.Cursor(ctx); err != nil {
		return d, err
	}
	d.CursorFloor = db.CursorFloor(ctx)
	d.DBBytes = db.SizeBytes()

	devices, err := db.ListDevices(ctx, "")
	if err != nil {
		return d, err
	}
	for _, dev := range devices {
		switch dev.Health(now) {
		case "online":
			d.DevicesOnline++
		case "lagging":
			d.DevicesLagging++
		case "offline", "never":
			d.DevicesOffline++
		}
	}
	d.RecentDevices = devices

	if d.Series, err = db.Series(ctx, hours); err != nil {
		return d, err
	}
	if d.TopCountries, err = db.TopCountries(ctx, 10); err != nil {
		return d, err
	}
	if d.TopASNs, err = db.TopASNs(ctx, 10); err != nil {
		return d, err
	}
	if d.TopAddresses, err = db.TopAddresses(ctx, 10); err != nil {
		return d, err
	}
	return d, nil
}

// Series returns one point per hour for the last n hours, oldest first, with
// gaps filled so the chart has a continuous axis.
func (db *DB) Series(ctx context.Context, hours int) ([]model.HourPoint, error) {
	if hours <= 0 || hours > 24*90 {
		hours = 48
	}
	now := time.Now().Unix()
	end := now - now%3600
	start := end - int64(hours-1)*3600

	rows, err := db.ro.QueryContext(ctx,
		`SELECT hour, reports, additions, removals FROM metrics_hourly
		 WHERE device_id = 0 AND hour >= ? ORDER BY hour`, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byHour := map[int64]model.HourPoint{}
	for rows.Next() {
		var p model.HourPoint
		if err := rows.Scan(&p.Hour, &p.Reports, &p.Additions, &p.Removals); err != nil {
			return nil, err
		}
		byHour[p.Hour] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.HourPoint, 0, hours)
	for h := start; h <= end; h += 3600 {
		if p, ok := byHour[h]; ok {
			out = append(out, p)
		} else {
			out = append(out, model.HourPoint{Hour: h})
		}
	}
	return out, nil
}

// TopCountries ranks countries by how many blocked addresses they hold.
func (db *DB) TopCountries(ctx context.Context, limit int) ([]model.CountryStat, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT country, COALESCE(MAX(country_name), ''), COUNT(*), COALESCE(SUM(report_count), 0)
		 FROM addresses WHERE state = 'blocked' AND country <> ''
		 GROUP BY country ORDER BY COUNT(*) DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.CountryStat
	for rows.Next() {
		var c model.CountryStat
		if err := rows.Scan(&c.Code, &c.Name, &c.Count, &c.Reports); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountryMap returns the full country breakdown for the choropleth.
func (db *DB) CountryMap(ctx context.Context) ([]model.CountryStat, error) {
	return db.TopCountries(ctx, 300)
}

// TopASNs ranks networks by how many blocked addresses they hold.
func (db *DB) TopASNs(ctx context.Context, limit int) ([]model.ASNStat, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT asn, COALESCE(MAX(asn_org), ''), COUNT(*), COALESCE(SUM(report_count), 0)
		 FROM addresses WHERE state = 'blocked' AND asn > 0
		 GROUP BY asn ORDER BY COUNT(*) DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ASNStat
	for rows.Next() {
		var a model.ASNStat
		if err := rows.Scan(&a.ASN, &a.Org, &a.Count, &a.Reports); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TopAddresses ranks the most persistent offenders: first by how many
// different routers saw them, then by total sightings.
func (db *DB) TopAddresses(ctx context.Context, limit int) ([]model.Address, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT `+addressCols+` FROM addresses WHERE state = 'blocked'
		 ORDER BY device_count DESC, report_count DESC, last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Address
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Activity returns the raw report stream, newest first.
func (db *DB) Activity(ctx context.Context, deviceID int64, limit, offset int) ([]model.ReportEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT e.id, e.at, e.device_id, COALESCE(d.name, '(deleted)'), e.address_id, e.ip, e.fresh
	      FROM report_events e LEFT JOIN devices d ON d.id = e.device_id`
	var args []any
	if deviceID > 0 {
		q += ` WHERE e.device_id = ?`
		args = append(args, deviceID)
	}
	q += ` ORDER BY e.at DESC, e.id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := db.ro.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ReportEvent
	for rows.Next() {
		var e model.ReportEvent
		if err := rows.Scan(&e.ID, &e.At, &e.DeviceID, &e.DeviceName, &e.AddressID, &e.IP, &e.Fresh); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeviceSeries returns the hourly activity of a single router.
func (db *DB) DeviceSeries(ctx context.Context, deviceID int64, hours int) ([]model.HourPoint, error) {
	if hours <= 0 || hours > 24*90 {
		hours = 48
	}
	now := time.Now().Unix()
	end := now - now%3600
	start := end - int64(hours-1)*3600
	rows, err := db.ro.QueryContext(ctx,
		`SELECT hour, reports, additions, removals FROM metrics_hourly
		 WHERE device_id = ? AND hour >= ? ORDER BY hour`, deviceID, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byHour := map[int64]model.HourPoint{}
	for rows.Next() {
		var p model.HourPoint
		if err := rows.Scan(&p.Hour, &p.Reports, &p.Additions, &p.Removals); err != nil {
			return nil, err
		}
		byHour[p.Hour] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.HourPoint, 0, hours)
	for h := start; h <= end; h += 3600 {
		if p, ok := byHour[h]; ok {
			out = append(out, p)
		} else {
			out = append(out, model.HourPoint{Hour: h})
		}
	}
	return out, nil
}

// PendingGeo returns addresses that have never been resolved, or whose
// resolution predates the given time, so the enricher can refresh them.
func (db *DB) PendingGeo(ctx context.Context, before int64, limit int) ([]model.Address, error) {
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	rows, err := db.ro.QueryContext(ctx,
		`SELECT `+addressCols+` FROM addresses WHERE geo_at < ? ORDER BY geo_at, id LIMIT ?`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Address
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GeoUpdate is one resolved address.
type GeoUpdate struct {
	ID          int64
	Country     string
	CountryName string
	Continent   string
	ASN         int64
	ASNOrg      string
}

// ApplyGeo writes a batch of resolutions in a single transaction.
func (db *DB) ApplyGeo(ctx context.Context, updates []GeoUpdate, now int64) error {
	if len(updates) == 0 {
		return nil
	}
	return db.tx(ctx, func(t *sql.Tx) error {
		stmt, err := t.PrepareContext(ctx,
			`UPDATE addresses SET country = ?, country_name = ?, continent = ?, asn = ?, asn_org = ?, geo_at = ?
			 WHERE id = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, u := range updates {
			if _, err := stmt.ExecContext(ctx, u.Country, u.CountryName, u.Continent,
				u.ASN, u.ASNOrg, now, u.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// ResetGeo clears the resolution stamp so every address is looked up again.
// Used after installing or replacing a geolocation database.
func (db *DB) ResetGeo(ctx context.Context) (int64, error) {
	r, err := db.rw.ExecContext(ctx, `UPDATE addresses SET geo_at = 0`)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
