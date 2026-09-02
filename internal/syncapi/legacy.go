package syncapi

import (
	"crypto/subtle"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/netutil"
	"github.com/alexwoo-awso/apb/internal/store"
)

// LegacyOptions configures the compatibility endpoint for routers still
// running the original APB scripts. It exists only to keep an estate reporting
// during a migration and is disabled unless explicitly turned on.
//
// The old protocol had one shared HTTP Basic credential for every router and
// no way to tell them apart, so everything it accepts is attributed to a
// single named device and the endpoint is upload-only: it can never hand out
// the blocklist. Turn it off once every router runs the new scripts.
type LegacyOptions struct {
	Enabled bool
	// Device is the name of the device row that legacy uploads are recorded
	// against. It must already exist.
	Device string
	// Authorization is the exact Authorization header the old scripts send,
	// for example "Basic dXNlcjpzZWNyZXQ=". Empty accepts any.
	Authorization string
	// UserAgent, when set, must match exactly, mirroring the old nginx gate.
	UserAgent string
}

// LegacyRoutes registers the compatibility endpoint at the original path.
func (a *API) LegacyRoutes(mux *http.ServeMux, opt LegacyOptions) {
	if !opt.Enabled {
		return
	}
	a.log.Warn("legacy upload endpoint enabled",
		"path", "/up.php", "device", opt.Device,
		"note", "shared credential, upload only; disable once every router runs the new scripts")

	mux.HandleFunc("POST /up.php", func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if opt.UserAgent != "" && r.UserAgent() != opt.UserAgent {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "-1")
			return
		}
		if opt.Authorization != "" {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(opt.Authorization)) != 1 {
				a.log.Warn("legacy upload rejected", "ip", ip, "reason", "authorization")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "0")
				return
			}
		}

		device, err := a.db.DeviceByName(r.Context(), opt.Device)
		if err != nil {
			a.log.Error("legacy upload has no device to attribute to",
				"device", opt.Device, "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "0")
			return
		}

		s := a.db.Settings()
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.MaxReportSize)+1))
		if err != nil || len(body) > s.MaxReportSize {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = io.WriteString(w, "0")
			return
		}

		res, err := a.db.Ingest(r.Context(), device.ID, netutil.SplitList(string(body)), time.Now().Unix())
		if err != nil {
			a.log.Error("legacy ingest", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "0")
			return
		}
		// The old scripts retry unless the body is exactly "1".
		a.log.Info("legacy upload accepted", "ip", ip, "device", device.Name,
			"file", clip(r.Header.Get("X-Filename"), 64),
			"accepted", res.Accepted, "new", res.NewAddresses)
		_, _ = io.WriteString(w, "1")
	})
}

// LegacyList serves the original snapshot paths so old apbGET scripts keep
// receiving additions during a migration. It is read-only and always reflects
// the current blocklist.
func (a *API) LegacyList(mux *http.ServeMux, opt LegacyOptions) {
	if !opt.Enabled {
		return
	}
	guard := func(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if opt.UserAgent != "" && r.UserAgent() != opt.UserAgent {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if opt.Authorization != "" &&
				subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(opt.Authorization)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			next(w, r)
		}
	}

	mux.HandleFunc("GET /r/manifest", guard(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "snapshots/add.csv,\n")
	}))

	mux.HandleFunc("GET /r/snapshots/add.csv", guard(func(w http.ResponseWriter, r *http.Request) {
		// The old client has no cursor, so it always receives the whole list.
		// It is capped because the old script reads the response into memory.
		var b strings.Builder
		var after int64
		for i := 0; i < 200; i++ {
			ips, next, more, err := a.db.SnapshotPage(r.Context(), after, 4096, false)
			if err != nil {
				a.log.Error("legacy snapshot", "err", err)
				break
			}
			for _, ip := range ips {
				b.WriteString(ip)
				b.WriteByte(',')
			}
			if !more {
				break
			}
			after = next
		}
		_, _ = io.WriteString(w, b.String())
	}))

	mux.HandleFunc("GET /r/snapshots/rem.csv", guard(func(w http.ResponseWriter, r *http.Request) {
		// Removals cannot be expressed in the old format without a cursor, so
		// this stays empty exactly as it always was. Routers that need removals
		// must move to the new scripts.
		_, _ = io.WriteString(w, ",\n")
	}))
}

var _ = store.ErrNotFound
