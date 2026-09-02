// Package config resolves the process-level configuration. Anything that can
// reasonably change while the service runs lives in the settings table
// instead; this struct only holds what must be known before the database is
// open.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the immutable process configuration.
type Config struct {
	Addr         string // listen address for the public/admin server
	MetricsAddr  string // optional separate listener for /metrics, "" disables
	DataDir      string // sqlite database, secret key, backups
	GeoDir       string // *.mmdb files
	BaseURL      string // public https URL, baked into generated scripts
	SecretKey    []byte // 32 bytes; seals TOTP secrets, HMACs device tokens
	TrustProxy   bool   // honour X-Forwarded-For / X-Real-IP
	RealIPHdr    string // header to read the client IP from when TrustProxy
	Dev          bool   // relaxes cookie Secure flag; never use in production
	LogLevel     string // debug | info | warn | error
	LogFormat    string // json | text
	Legacy       bool   // enable the /up.php compatibility endpoint
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// Load reads the environment and prepares the data directory.
func Load() (*Config, error) {
	c := &Config{
		Addr:         env("APB_ADDR", ":8080"),
		MetricsAddr:  env("APB_METRICS_ADDR", ""),
		DataDir:      env("APB_DATA_DIR", "/data"),
		GeoDir:       env("APB_GEO_DIR", ""),
		BaseURL:      strings.TrimRight(env("APB_BASE_URL", ""), "/"),
		TrustProxy:   envBool("APB_TRUST_PROXY", false),
		RealIPHdr:    env("APB_REAL_IP_HEADER", "X-Forwarded-For"),
		Dev:          envBool("APB_DEV", false),
		LogLevel:     strings.ToLower(env("APB_LOG_LEVEL", "info")),
		LogFormat:    strings.ToLower(env("APB_LOG_FORMAT", "json")),
		Legacy:       envBool("APB_LEGACY_UPLOAD", false),
		ReadTimeout:  envDur("APB_READ_TIMEOUT", 15*time.Second),
		WriteTimeout: envDur("APB_WRITE_TIMEOUT", 60*time.Second),
		IdleTimeout:  envDur("APB_IDLE_TIMEOUT", 90*time.Second),
	}
	if c.GeoDir == "" {
		c.GeoDir = filepath.Join(c.DataDir, "geo")
	}
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	if err := os.MkdirAll(c.GeoDir, 0o700); err != nil {
		return nil, fmt.Errorf("geo dir: %w", err)
	}
	key, err := resolveSecret(c.DataDir)
	if err != nil {
		return nil, err
	}
	c.SecretKey = key
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return nil, errors.New("APB_BASE_URL must include the scheme, e.g. https://apb.example.org")
	}
	return c, nil
}

// DBPath is the location of the SQLite database file.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "apb.db") }

// resolveSecret prefers APB_SECRET_KEY and otherwise generates a persistent
// key under the data directory. Losing this key invalidates every enrolled
// TOTP secret and every issued device token, so it is written 0600 and never
// logged.
func resolveSecret(dataDir string) ([]byte, error) {
	if raw := os.Getenv("APB_SECRET_KEY"); raw != "" {
		key, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return nil, errors.New("APB_SECRET_KEY must be hex encoded (see: openssl rand -hex 32)")
		}
		if len(key) < 32 {
			return nil, errors.New("APB_SECRET_KEY must decode to at least 32 bytes")
		}
		return key, nil
	}
	path := filepath.Join(dataDir, "secret.key")
	if b, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) < 32 {
			return nil, fmt.Errorf("%s is corrupt; remove it only if you accept losing every TOTP enrolment and device token", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read secret key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write secret key: %w", err)
	}
	return key, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

func envDur(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return def
	}
	return d
}
