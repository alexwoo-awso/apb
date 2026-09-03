package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Settings is the operator-tunable configuration held in the database and
// editable from the web console. It is cached in memory and refreshed on every
// write, so hot paths read it without touching SQLite.
type Settings struct {
	InstanceName string `key:"instance_name" label:"Instance name" help:"Shown in the header and in generated scripts."`

	AutoBlockReports int `key:"auto_block_reports" label:"Reports before broadcast" help:"How many reports an address needs before it is pushed to the routers. 1 broadcasts immediately."`
	AutoBlockDevices int `key:"auto_block_devices" label:"Distinct routers before broadcast" help:"How many different routers must have reported an address before it is pushed. Raise this to require corroboration."`
	DefaultTTLDays   int `key:"default_ttl_days" label:"Server-side block lifetime (days)" help:"An address not seen again for this long is released and removed from every router. 0 keeps entries forever."`

	DefaultBlockTimeout   string `key:"default_block_timeout" label:"RouterOS entry timeout" help:"Timeout written into each address-list entry, which is what keeps it in RAM instead of flash. RouterOS refuses a long value and then holds nothing, so this stays short: 4w works everywhere tested, 8w is the largest observed to work anywhere."`
	DefaultSyncInterval   int    `key:"default_sync_interval" label:"Default sync interval (s)" help:"How often a new router polls for changes. Lower is closer to real time; 15s is a good balance."`
	DefaultReportInterval int    `key:"default_report_interval" label:"Default report interval (s)" help:"How often a new router uploads its own detections."`
	DefaultListName       string `key:"default_list_name" label:"Default address-list name" help:"Name of the RouterOS address list that receives blocked addresses."`
	DefaultDetectList     string `key:"default_detect_list" label:"Default detection list name" help:"Name of the local RouterOS address list your firewall rules populate with abusers."`

	MaxSyncBytes  int `key:"max_sync_bytes" label:"Max sync payload (bytes)" help:"Hard cap on a single sync response. RouterOS truncates fetch output above roughly 20 KB, so keep this well below that."`
	MaxReportSize int `key:"max_report_size" label:"Max report upload (bytes)" help:"Largest body accepted from a router on the report endpoint."`

	ChangeRetentionDays int `key:"change_retention_days" label:"Changelog retention (days)" help:"How long replication history is kept. A router offline for longer than this performs a full resync instead."`
	EventRetentionDays  int `key:"event_retention_days" label:"Activity retention (days)" help:"How long the raw per-report activity stream is kept."`
	AuditRetentionDays  int `key:"audit_retention_days" label:"Audit log retention (days)" help:"How long administrative actions are kept."`

	RequireUserAgent string `key:"require_user_agent" label:"Required client User-Agent" help:"When set, router requests must carry this exact User-Agent. Defence in depth only, never a substitute for the token. Leave empty to disable."`

	SessionIdleMinutes int `key:"session_idle_minutes" label:"Console idle timeout (min)" help:"An idle console session is signed out after this long."`
	SessionMaxHours    int `key:"session_max_hours" label:"Console session lifetime (h)" help:"Absolute lifetime of a console session regardless of activity."`
	LoginMaxAttempts   int `key:"login_max_attempts" label:"Failed logins before lockout" help:"Consecutive failures that lock an account."`
	LoginLockMinutes   int `key:"login_lock_minutes" label:"Lockout duration (min)" help:"How long a locked account stays locked."`

	GeoEnabled    bool   `key:"geo_enabled" label:"Enable IP geolocation" help:"Resolve country and network operator for each address using a local database. No queries ever leave this server."`
	GeoAutoUpdate bool   `key:"geo_auto_update" label:"Auto-update geo databases" help:"Download refreshed country and ASN databases weekly."`
	GeoCountryURL string `key:"geo_country_url" label:"Country database URL" help:"Source for the IP-to-country MMDB file."`
	GeoASNURL     string `key:"geo_asn_url" label:"ASN database URL" help:"Source for the IP-to-ASN MMDB file."`
}

// DefaultSettings returns the shipped defaults.
func DefaultSettings() Settings {
	return Settings{
		InstanceName:          "APB",
		AutoBlockReports:      1,
		AutoBlockDevices:      1,
		DefaultTTLDays:        0,
		DefaultBlockTimeout:   "4w",
		DefaultSyncInterval:   15,
		DefaultReportInterval: 300,
		DefaultListName:       "APB",
		DefaultDetectList:     "APB_detect",
		MaxSyncBytes:          8192,
		MaxReportSize:         262144,
		ChangeRetentionDays:   30,
		EventRetentionDays:    30,
		AuditRetentionDays:    180,
		RequireUserAgent:      "",
		SessionIdleMinutes:    60,
		SessionMaxHours:       12,
		LoginMaxAttempts:      8,
		LoginLockMinutes:      15,
		GeoEnabled:            true,
		GeoAutoUpdate:         false,
		GeoCountryURL:         "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country-mmdb/dbip-country.mmdb",
		GeoASNURL:             "https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn.mmdb",
	}
}

type atomicSettings struct{ v atomic.Pointer[Settings] }

// Settings returns the cached snapshot.
func (db *DB) Settings() Settings {
	if p := db.settings.v.Load(); p != nil {
		return *p
	}
	return DefaultSettings()
}

func (db *DB) loadSettings(ctx context.Context) error {
	s := DefaultSettings()
	rows, err := db.rw.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	kv := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		kv[k] = v
	}
	if err := rows.Err(); err != nil {
		return err
	}
	applyKV(&s, kv)
	db.settings.v.Store(&s)
	return nil
}

// SaveSettings persists the provided values and refreshes the cache. Only keys
// present in kv are written; the rest keep their stored value.
func (db *DB) SaveSettings(ctx context.Context, kv map[string]string) error {
	now := time.Now().Unix()
	err := db.tx(ctx, func(t *sql.Tx) error {
		stmt, err := t.PrepareContext(ctx,
			`INSERT INTO settings(key, value, updated_at) VALUES(?, ?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for k, v := range kv {
			if !knownSettingKey(k) {
				continue
			}
			if _, err := stmt.ExecContext(ctx, k, v, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return db.loadSettings(ctx)
}

// SettingsMap renders the current settings as the flat key/value form used by
// the settings form.
func (s Settings) Map() map[string]string {
	return map[string]string{
		"instance_name":           s.InstanceName,
		"auto_block_reports":      strconv.Itoa(s.AutoBlockReports),
		"auto_block_devices":      strconv.Itoa(s.AutoBlockDevices),
		"default_ttl_days":        strconv.Itoa(s.DefaultTTLDays),
		"default_block_timeout":   s.DefaultBlockTimeout,
		"default_sync_interval":   strconv.Itoa(s.DefaultSyncInterval),
		"default_report_interval": strconv.Itoa(s.DefaultReportInterval),
		"default_list_name":       s.DefaultListName,
		"default_detect_list":     s.DefaultDetectList,
		"max_sync_bytes":          strconv.Itoa(s.MaxSyncBytes),
		"max_report_size":         strconv.Itoa(s.MaxReportSize),
		"change_retention_days":   strconv.Itoa(s.ChangeRetentionDays),
		"event_retention_days":    strconv.Itoa(s.EventRetentionDays),
		"audit_retention_days":    strconv.Itoa(s.AuditRetentionDays),
		"require_user_agent":      s.RequireUserAgent,
		"session_idle_minutes":    strconv.Itoa(s.SessionIdleMinutes),
		"session_max_hours":       strconv.Itoa(s.SessionMaxHours),
		"login_max_attempts":      strconv.Itoa(s.LoginMaxAttempts),
		"login_lock_minutes":      strconv.Itoa(s.LoginLockMinutes),
		"geo_enabled":             boolStr(s.GeoEnabled),
		"geo_auto_update":         boolStr(s.GeoAutoUpdate),
		"geo_country_url":         s.GeoCountryURL,
		"geo_asn_url":             s.GeoASNURL,
	}
}

func knownSettingKey(k string) bool {
	_, ok := DefaultSettings().Map()[k]
	return ok
}

func applyKV(s *Settings, kv map[string]string) {
	str := func(k string, dst *string) {
		if v, ok := kv[k]; ok {
			*dst = v
		}
	}
	num := func(k string, dst *int, min, max int) {
		v, ok := kv[k]
		if !ok {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return
		}
		if n < min {
			n = min
		}
		if n > max {
			n = max
		}
		*dst = n
	}
	bl := func(k string, dst *bool) {
		if v, ok := kv[k]; ok {
			*dst = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
		}
	}

	str("instance_name", &s.InstanceName)
	num("auto_block_reports", &s.AutoBlockReports, 1, 1000)
	num("auto_block_devices", &s.AutoBlockDevices, 1, 1000)
	num("default_ttl_days", &s.DefaultTTLDays, 0, 3650)
	str("default_block_timeout", &s.DefaultBlockTimeout)
	num("default_sync_interval", &s.DefaultSyncInterval, 5, 3600)
	num("default_report_interval", &s.DefaultReportInterval, 30, 86400)
	str("default_list_name", &s.DefaultListName)
	str("default_detect_list", &s.DefaultDetectList)
	num("max_sync_bytes", &s.MaxSyncBytes, 512, 16384)
	num("max_report_size", &s.MaxReportSize, 1024, 8*1024*1024)
	num("change_retention_days", &s.ChangeRetentionDays, 1, 3650)
	num("event_retention_days", &s.EventRetentionDays, 1, 3650)
	num("audit_retention_days", &s.AuditRetentionDays, 1, 3650)
	str("require_user_agent", &s.RequireUserAgent)
	num("session_idle_minutes", &s.SessionIdleMinutes, 5, 1440)
	num("session_max_hours", &s.SessionMaxHours, 1, 720)
	num("login_max_attempts", &s.LoginMaxAttempts, 3, 100)
	num("login_lock_minutes", &s.LoginLockMinutes, 1, 1440)
	bl("geo_enabled", &s.GeoEnabled)
	bl("geo_auto_update", &s.GeoAutoUpdate)
	str("geo_country_url", &s.GeoCountryURL)
	str("geo_asn_url", &s.GeoASNURL)
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
