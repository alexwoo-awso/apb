// Package store owns every SQL statement in APB2. Callers work with the
// methods on DB; no other package builds queries.
//
// Concurrency model: SQLite in WAL mode allows many readers and exactly one
// writer, so the store keeps two pools — a single-connection writer and a
// multi-connection reader. Writers never block readers and vice versa.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// DB is the APB2 data store.
type DB struct {
	rw   *sql.DB
	ro   *sql.DB
	path string
	log  *slog.Logger

	settings atomicSettings
}

// Open prepares the database at path, applying any pending migrations.
func Open(path string, log *slog.Logger) (*DB, error) {
	if log == nil {
		log = slog.Default()
	}
	rw, err := openPool(path, false, 1)
	if err != nil {
		return nil, err
	}
	db := &DB{rw: rw, path: path, log: log}
	if err := db.migrate(); err != nil {
		rw.Close()
		return nil, err
	}
	ro, err := openPool(path, true, 8)
	if err != nil {
		rw.Close()
		return nil, err
	}
	db.ro = ro
	if err := db.loadSettings(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func openPool(path string, readonly bool, maxConns int) (*sql.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "temp_store(MEMORY)")
	// 16 MiB of page cache: plenty for the working set, still a small RSS.
	q.Add("_pragma", "cache_size(-16000)")
	if readonly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rwc")
		q.Add("_txlock", "immediate")
	}
	dsn := "file:" + filepathToURI(path) + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return db, nil
}

// filepathToURI normalises Windows separators so the same DSN works on every
// platform we build for.
func filepathToURI(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// Close releases both pools.
func (db *DB) Close() error {
	var errs []error
	if db.ro != nil {
		errs = append(errs, db.ro.Close())
	}
	if db.rw != nil {
		errs = append(errs, db.rw.Close())
	}
	return errors.Join(errs...)
}

// Path is the on-disk location of the database.
func (db *DB) Path() string { return db.path }

// SizeBytes reports the size of the database file plus its WAL.
func (db *DB) SizeBytes() int64 {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(db.path + suffix); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// Reader exposes the read-only pool for callers that need raw access.
func (db *DB) Reader() *sql.DB { return db.ro }

// tx runs fn inside an immediate write transaction.
func (db *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := db.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = t.Rollback() }()
	if err := fn(t); err != nil {
		return err
	}
	return t.Commit()
}

// ---------------------------------------------------------------- migrations

type migration struct {
	name string
	body string
}

func (db *DB) migrate() error {
	ctx := context.Background()
	if _, err := db.rw.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("migration table: %w", err)
	}
	applied := map[string]bool{}
	rows, err := db.rw.QueryContext(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		applied[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var pending []migration
	err = fs.WalkDir(migrationFS, "migrations", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".sql") {
			return err
		}
		name := strings.TrimPrefix(p, "migrations/")
		if applied[name] {
			return nil
		}
		b, err := migrationFS.ReadFile(p)
		if err != nil {
			return err
		}
		pending = append(pending, migration{name: name, body: string(b)})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].name < pending[j].name })

	for _, m := range pending {
		db.log.Info("applying migration", "name", m.name)
		t, err := db.rw.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, m.body); err != nil {
			t.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := t.ExecContext(ctx,
			`INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`,
			m.name, time.Now().Unix()); err != nil {
			t.Rollback()
			return fmt.Errorf("migration %s bookkeeping: %w", m.name, err)
		}
		if err := t.Commit(); err != nil {
			return fmt.Errorf("migration %s commit: %w", m.name, err)
		}
	}
	return nil
}

// Maintain runs the periodic housekeeping: expiry, retention pruning and a
// WAL checkpoint. It is safe to call concurrently with normal traffic.
func (db *DB) Maintain(ctx context.Context) error {
	s := db.Settings()
	now := time.Now().Unix()

	if n, err := db.ExpireAddresses(ctx, now); err != nil {
		return fmt.Errorf("expire addresses: %w", err)
	} else if n > 0 {
		db.log.Info("expired addresses", "count", n)
	}
	if n, err := db.ExpireWhitelist(ctx, now); err != nil {
		return fmt.Errorf("expire whitelist: %w", err)
	} else if n > 0 {
		db.log.Info("expired whitelist entries", "count", n)
	}
	if s.ChangeRetentionDays > 0 {
		cutoff := now - int64(s.ChangeRetentionDays)*86400
		// Record how far history was trimmed before trimming it: a router whose
		// cursor falls below this point has provably missed changes and is told
		// to resynchronise from scratch instead of silently drifting.
		var highest int64
		if err := db.rw.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(seq), 0) FROM changes WHERE at < ?`, cutoff).Scan(&highest); err != nil {
			return fmt.Errorf("changelog floor: %w", err)
		}
		if highest > 0 {
			if err := db.SetCursorFloor(ctx, highest); err != nil {
				return fmt.Errorf("set changelog floor: %w", err)
			}
			if _, err := db.rw.ExecContext(ctx, `DELETE FROM changes WHERE at < ?`, cutoff); err != nil {
				return fmt.Errorf("prune changes: %w", err)
			}
		}
	}
	if s.EventRetentionDays > 0 {
		cutoff := now - int64(s.EventRetentionDays)*86400
		if _, err := db.rw.ExecContext(ctx, `DELETE FROM report_events WHERE at < ?`, cutoff); err != nil {
			return fmt.Errorf("prune events: %w", err)
		}
		if _, err := db.rw.ExecContext(ctx, `DELETE FROM metrics_hourly WHERE hour < ?`, now-400*86400); err != nil {
			return fmt.Errorf("prune metrics: %w", err)
		}
	}
	if _, err := db.rw.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now); err != nil {
		return fmt.Errorf("prune sessions: %w", err)
	}
	if _, err := db.rw.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, now-int64(max(s.AuditRetentionDays, 1))*86400); err != nil {
		return fmt.Errorf("prune audit: %w", err)
	}
	if _, err := db.rw.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		db.log.Warn("wal checkpoint", "err", err)
	}
	return nil
}

// Backup writes a consistent copy of the database to dst using the online
// backup API exposed through VACUUM INTO.
func (db *DB) Backup(ctx context.Context, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	_, err := db.rw.ExecContext(ctx, `VACUUM INTO ?`, filepathToURI(dst))
	return err
}

// Integrity runs a quick consistency check.
func (db *DB) Integrity(ctx context.Context) (string, error) {
	var out string
	err := db.ro.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&out)
	return out, err
}
