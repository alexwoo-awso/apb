package adminui

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/geo"
)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	cfg := s.db.Settings()
	cursor, _ := s.db.Cursor(r.Context())
	integrity, _ := s.db.Integrity(r.Context())
	s.render(w, r, sc, "settings.html", "Settings", "settings", map[string]any{
		"S":           cfg,
		"Values":      cfg.Map(),
		"Geo":         s.geo.Status(),
		"Cursor":      cursor,
		"CursorFloor": s.db.CursorFloor(r.Context()),
		"DBBytes":     s.db.SizeBytes(),
		"DBPath":      s.db.Path(),
		"Integrity":   integrity,
		"BaseURL":     s.baseURL(r),
	})
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	current := s.db.Settings().Map()
	next := make(map[string]string, len(current))
	for key := range current {
		switch key {
		case "geo_enabled", "geo_auto_update":
			next[key] = boolField(r, key)
		default:
			next[key] = strings.TrimSpace(r.PostFormValue(key))
		}
	}
	if err := s.db.SaveSettings(r.Context(), next); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not save the settings")
		return
	}
	var changed []string
	saved := s.db.Settings().Map()
	for k, v := range saved {
		if current[k] != v {
			changed = append(changed, k)
		}
	}
	s.audit(r, sc, "settings.update", strings.Join(changed, ","), "", true)
	if len(changed) == 0 {
		s.flash(sc, "ok", "Nothing changed.")
	} else {
		s.flash(sc, "ok", "Saved %d setting(s). They take effect immediately.", len(changed))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// postSettingsGeo installs or refreshes the geolocation databases. The
// download runs in the background because it can take a minute, and the page
// would otherwise appear to hang.
func (s *Server) postSettingsGeo(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	cfg := s.db.Settings()
	switch r.PostFormValue("op") {
	case "download":
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			for _, job := range []struct{ url, name string }{
				{cfg.GeoCountryURL, geo.CountryFile},
				{cfg.GeoASNURL, geo.ASNFile},
			} {
				if job.url == "" {
					continue
				}
				if err := s.geo.Download(ctx, job.url, job.name); err != nil {
					s.log.Error("geo download failed", "file", job.name, "err", err)
					continue
				}
				s.log.Info("geo database updated", "file", job.name)
			}
			if _, err := s.db.ResetGeo(ctx); err != nil {
				s.log.Error("geo reset", "err", err)
			}
		}()
		s.audit(r, sc, "settings.geo_download", "", cfg.GeoCountryURL+" "+cfg.GeoASNURL, true)
		s.flash(sc, "ok", "Downloading the geolocation databases in the background. Reload this page in a minute to see the result.")

	case "reload":
		if err := s.geo.Reload(); err != nil {
			s.flash(sc, "err", "%s", err.Error())
		} else {
			s.flash(sc, "ok", "Reloaded the geolocation databases from disk.")
		}
		s.audit(r, sc, "settings.geo_reload", "", "", true)

	case "reresolve":
		n, err := s.db.ResetGeo(r.Context())
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "could not queue the re-resolution")
			return
		}
		s.audit(r, sc, "settings.geo_reresolve", "", "", true)
		s.flash(sc, "ok", "Queued %d address(es) to be located again; this happens in the background.", n)

	default:
		s.flash(sc, "err", "Unknown operation.")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func boolField(r *http.Request, name string) string {
	if formBool(r, name) {
		return "1"
	}
	return "0"
}
