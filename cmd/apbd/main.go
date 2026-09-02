// Command apbd is the APB server: the router-facing sync API and the web
// console, in one process with no external dependencies beyond its data
// directory.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexwoo-awso/apb/internal/adminui"
	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/config"
	"github.com/alexwoo-awso/apb/internal/geo"
	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/store"
	"github.com/alexwoo-awso/apb/internal/syncapi"
	"github.com/alexwoo-awso/apb/internal/version"
)

func main() {
	// Two tiny modes that need no configuration, so the container image can
	// answer a health check and report its build without shipping a shell.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version", "version":
			fmt.Println(version.String())
			return
		case "-healthcheck", "--healthcheck", "healthcheck":
			if err := healthcheck(); err != nil {
				fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "apbd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	slog.SetDefault(log)
	log.Info("starting", "version", version.String(), "addr", cfg.Addr, "data", cfg.DataDir)

	db, err := store.Open(cfg.DBPath(), log)
	if err != nil {
		return err
	}
	defer db.Close()

	keys, err := auth.NewKeyring(cfg.SecretKey)
	if err != nil {
		return err
	}

	resolver := geo.New(cfg.GeoDir, log)
	defer resolver.Close()
	if c, a := resolver.Ready(); !c && !a {
		log.Warn("no geolocation database installed",
			"dir", cfg.GeoDir,
			"note", "blocking works without it; install one from the settings page to see countries and networks")
	}

	console, err := adminui.New(db, keys, resolver, adminui.Options{
		BaseURL:    cfg.BaseURL,
		SecureOnly: !cfg.Dev,
		Log:        log,
	})
	if err != nil {
		return err
	}
	if n, err := db.CountAdmins(context.Background()); err == nil && n == 0 {
		code := os.Getenv("APB_SETUP_CODE")
		if code == "" {
			code, err = setupCode()
			if err != nil {
				return err
			}
		}
		console.SetupCode = code
		log.Warn("no administrator exists yet",
			"open", firstNonEmpty(cfg.BaseURL, "http://localhost"+cfg.Addr)+"/setup",
			"setup code", code)
	}

	api := syncapi.New(db, keys, log)

	mux := http.NewServeMux()
	api.Routes(mux)
	console.Routes(mux)

	legacy := syncapi.LegacyOptions{
		Enabled:       cfg.Legacy,
		Device:        os.Getenv("APB_LEGACY_DEVICE"),
		Authorization: os.Getenv("APB_LEGACY_AUTH"),
		UserAgent:     os.Getenv("APB_LEGACY_USER_AGENT"),
	}
	if legacy.Enabled && legacy.Device == "" {
		return errors.New("APB_LEGACY_UPLOAD is on but APB_LEGACY_DEVICE names no device to attribute uploads to")
	}
	api.LegacyRoutes(mux, legacy)
	api.LegacyList(mux, legacy)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := db.Cursor(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	handler := httpx.Chain(mux,
		httpx.Recover(log),
		httpx.RealIP(cfg.TrustProxy, cfg.RealIPHdr),
		httpx.Logger(log),
		httpx.SecurityHeaders(!cfg.Dev),
		httpx.MaxBody(8<<20),
	)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go background(ctx, db, resolver, log)

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// background runs the periodic work: geolocation enrichment, retention and
// the optional database refresh. Each tick is independent, so a failure in one
// never stops the others.
func background(ctx context.Context, db *store.DB, resolver *geo.Resolver, log *slog.Logger) {
	enrich := time.NewTicker(20 * time.Second)
	maintain := time.NewTicker(time.Hour)
	geoUpdate := time.NewTicker(24 * time.Hour)
	defer enrich.Stop()
	defer maintain.Stop()
	defer geoUpdate.Stop()

	// Run maintenance once at startup so a service that has been down for a
	// while catches up on expiry immediately rather than in an hour.
	if err := db.Maintain(ctx); err != nil {
		log.Error("maintenance", "err", err)
	}

	var lastGeo time.Time
	for {
		select {
		case <-ctx.Done():
			return

		case <-enrich.C:
			if !db.Settings().GeoEnabled {
				continue
			}
			n, err := geo.Enrich(ctx, db, resolver, 500, 90*24*time.Hour)
			if err != nil {
				log.Error("geolocation", "err", err)
			} else if n > 0 {
				log.Debug("located addresses", "count", n)
			}

		case <-maintain.C:
			if err := db.Maintain(ctx); err != nil {
				log.Error("maintenance", "err", err)
			}

		case <-geoUpdate.C:
			s := db.Settings()
			if !s.GeoAutoUpdate || time.Since(lastGeo) < 7*24*time.Hour {
				continue
			}
			lastGeo = time.Now()
			for _, job := range []struct{ url, name string }{
				{s.GeoCountryURL, geo.CountryFile},
				{s.GeoASNURL, geo.ASNFile},
			} {
				if job.url == "" {
					continue
				}
				if err := resolver.Download(ctx, job.url, job.name); err != nil {
					log.Error("geo update", "file", job.name, "err", err)
				}
			}
		}
	}
}

// healthcheck asks the local listener whether it is serving. It exists so the
// container needs neither curl nor a shell.
func healthcheck() error {
	addr := os.Getenv("APB_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

// setupCode mints the one-time code that gates first-run account creation, so
// an instance exposed to the internet before anyone signs in cannot be claimed
// by whoever finds it first.
func setupCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return strings.ToLower(code[:4] + "-" + code[4:8] + "-" + code[8:12]), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
