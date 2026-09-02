// Package adminui serves the web console: the dashboard, the blocklist and
// whitelist views, device provisioning and script generation, account
// management, settings and the audit trail.
//
// Every page is rendered on the server. The only client-side code is a small
// progressive-enhancement script for table selection and dismissing the
// explainer cards, so the content security policy can forbid inline script and
// every third-party origin.
package adminui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/geo"
	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/store"
	"github.com/alexwoo-awso/apb/internal/version"
	"github.com/alexwoo-awso/apb/web"
)

var worldSVG = web.WorldSVG

// assetTag fingerprints the stylesheet and script so an upgraded binary is
// never served with a browser's cached copy of the old ones. Static files are
// cached for an hour, which is only safe because this tag changes with them.
var assetTag = func() string {
	h := sha256.New()
	for _, name := range []string{"static/app.css", "static/app.js"} {
		b, err := web.Static.ReadFile(name)
		if err != nil {
			return "dev"
		}
		h.Write(b)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:10]
}()

// Options configures the console.
type Options struct {
	BaseURL    string
	SecureOnly bool // set the Secure flag on cookies; off only for local http
	Log        *slog.Logger
}

// Server is the console handler set.
type Server struct {
	db   *store.DB
	keys *auth.Keyring
	geo  *geo.Resolver
	opt  Options
	log  *slog.Logger

	tmpl     *template.Template
	loginLim *httpx.Limiter
	totpUsed usedTOTP

	// SetupCode gates the first-run account creation. It is printed to the log
	// at startup while no administrator exists, and cleared once one is made.
	SetupCode string

	flashMu sync.Mutex
	flashes map[string][]flash
}

type flash struct {
	Kind string // ok | warn | err
	Text string
	At   time.Time
}

// New builds the console.
func New(db *store.DB, keys *auth.Keyring, resolver *geo.Resolver, opt Options) (*Server, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	t, err := template.New("").Funcs(funcs).ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{
		db:       db,
		keys:     keys,
		geo:      resolver,
		opt:      opt,
		log:      opt.Log,
		tmpl:     t,
		loginLim: httpx.NewLimiter(0.2, 8),
		flashes:  map[string][]flash{},
	}, nil
}

// Routes registers every console route on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	static, err := fs.Sub(web.Static, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))

	// Unauthenticated.
	mux.HandleFunc("GET /setup", s.getSetup)
	mux.HandleFunc("POST /setup", s.postSetup)
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("GET /login/2fa", s.getLoginTOTP)
	mux.HandleFunc("POST /login/2fa", s.postLoginTOTP)
	mux.HandleFunc("POST /logout", s.postLogout)

	// Enrolment: reachable while signed in but not yet carrying a second factor.
	mux.Handle("GET /account/2fa", s.half(s.getEnroll))
	mux.Handle("POST /account/2fa", s.half(s.postEnroll))
	mux.Handle("GET /account/2fa/qr.png", s.half(s.getEnrollQR))

	// Read-only pages.
	mux.Handle("GET /{$}", s.auth(s.getDashboard))
	mux.Handle("GET /addresses", s.auth(s.getAddresses))
	mux.Handle("GET /addresses/export", s.auth(s.getAddressExport))
	mux.Handle("GET /addresses/{id}", s.auth(s.getAddress))
	mux.Handle("GET /whitelist", s.auth(s.getWhitelist))
	mux.Handle("GET /whitelist/preview", s.auth(s.getWhitelistPreview))
	mux.Handle("GET /devices", s.auth(s.getDevices))
	mux.Handle("GET /devices/{id}", s.auth(s.getDevice))
	mux.Handle("GET /devices/{id}/scripts", s.auth(s.getDeviceScripts))
	mux.Handle("GET /activity", s.auth(s.getActivity))
	mux.Handle("GET /audit", s.auth(s.getAudit))
	mux.Handle("GET /users", s.auth(s.getUsers))
	mux.Handle("GET /settings", s.auth(s.getSettings))
	mux.Handle("GET /account", s.auth(s.getAccount))
	mux.Handle("GET /help", s.auth(s.getHelp))

	// Mutations. Each of these checks the CSRF token and the write role.
	mux.Handle("POST /addresses", s.write(s.postAddressAdd))
	mux.Handle("POST /addresses/action", s.write(s.postAddressAction))
	mux.Handle("POST /addresses/{id}/notes", s.write(s.postAddressNotes))
	mux.Handle("POST /whitelist", s.write(s.postWhitelistAdd))
	mux.Handle("POST /whitelist/{id}/delete", s.write(s.postWhitelistDelete))
	mux.Handle("POST /devices", s.write(s.postDeviceCreate))
	mux.Handle("POST /devices/{id}", s.write(s.postDeviceUpdate))
	mux.Handle("POST /devices/{id}/delete", s.write(s.postDeviceDelete))
	mux.Handle("POST /devices/{id}/tokens", s.write(s.postTokenCreate))
	mux.Handle("POST /devices/{id}/tokens/{tid}/revoke", s.write(s.postTokenRevoke))
	mux.Handle("POST /devices/{id}/scripts", s.write(s.postDeviceScripts))
	mux.Handle("POST /users", s.write(s.postUserCreate))
	mux.Handle("POST /users/{id}", s.write(s.postUserUpdate))
	mux.Handle("POST /users/{id}/delete", s.write(s.postUserDelete))
	mux.Handle("POST /users/{id}/unlock", s.write(s.postUserUnlock))
	mux.Handle("POST /users/{id}/reset2fa", s.write(s.postUserReset2FA))
	mux.Handle("POST /users/{id}/sessions", s.write(s.postUserSessions))
	mux.Handle("POST /settings", s.write(s.postSettings))
	mux.Handle("POST /settings/geo", s.write(s.postSettingsGeo))
	mux.Handle("POST /account/password", s.auth(s.postAccountPassword))
	mux.Handle("POST /hints/dismiss", s.auth(s.postHintDismiss))
	mux.Handle("POST /hints/reset", s.auth(s.postHintReset))
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------------- context

type sessionCtx struct {
	session model.Session
	admin   model.Admin
	hints   map[string]bool
}

type ctxKey int

const ctxSession ctxKey = iota

func sessionFrom(r *http.Request) *sessionCtx {
	v, _ := r.Context().Value(ctxSession).(*sessionCtx)
	return v
}

type authedHandler func(http.ResponseWriter, *http.Request, *sessionCtx)

// auth requires a fully authenticated session.
func (s *Server) auth(next authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, ok := s.resolve(w, r)
		if !ok {
			return
		}
		if sc.session.PendingTOTP {
			http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
			return
		}
		if !sc.admin.TOTPEnrolled {
			// Two-factor authentication is mandatory, so an account without it
			// can reach nothing but its own enrolment page.
			http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxSession, sc)), sc)
	})
}

// half allows a session that has passed the password step but not yet the
// second factor, which is what the enrolment pages need.
func (s *Server) half(next authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, ok := s.resolve(w, r)
		if !ok {
			return
		}
		if sc.session.PendingTOTP {
			http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
			return
		}
		if sc.admin.TOTPEnrolled {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxSession, sc)), sc)
	})
}

// write wraps auth with a CSRF check and a role check.
func (s *Server) write(next authedHandler) http.Handler {
	return s.auth(func(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
		if err := r.ParseForm(); err != nil {
			s.fail(w, r, http.StatusBadRequest, "malformed form submission")
			return
		}
		if !auth.ConstantTimeEqual(r.PostFormValue("csrf"), sc.session.CSRF) {
			s.log.Warn("csrf rejected", "admin", sc.admin.Username, "path", r.URL.Path, "ip", httpx.ClientIP(r))
			s.fail(w, r, http.StatusForbidden, "this form has expired, please reload the page and try again")
			return
		}
		if !sc.admin.CanWrite() {
			s.fail(w, r, http.StatusForbidden, "your account has read-only access")
			return
		}
		next(w, r, sc)
	})
}

// resolve loads the session and its account, redirecting when there is none.
func (s *Server) resolve(w http.ResponseWriter, r *http.Request) (*sessionCtx, bool) {
	ctx := r.Context()
	if n, err := s.db.CountAdmins(ctx); err == nil && n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return nil, false
	}
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		s.redirectToLogin(w, r)
		return nil, false
	}
	cfg := s.db.Settings()
	sess, err := s.db.Session(ctx, s.keys.SessionHash(c.Value), int64(cfg.SessionIdleMinutes)*60)
	if err != nil {
		s.clearCookie(w)
		s.redirectToLogin(w, r)
		return nil, false
	}
	admin, err := s.db.AdminByID(ctx, sess.AdminID)
	if err != nil || admin.Disabled {
		_ = s.db.DeleteSession(ctx, sess.ID)
		s.clearCookie(w)
		s.redirectToLogin(w, r)
		return nil, false
	}
	s.db.TouchSession(ctx, sess.ID, time.Now().Unix())
	hints, _ := s.db.HintsSeen(ctx, admin.ID)
	return &sessionCtx{session: sess, admin: admin, hints: hints}, true
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.RequestURI()
	if r.Method != http.MethodGet || next == "/" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

// -------------------------------------------------------------------- render

type page struct {
	Asset    string
	Title    string
	Nav      string
	Admin    model.Admin
	CSRF     string
	Flashes  []flash
	Hints    map[string]bool
	Settings store.Settings
	Instance string
	Version  string
	Now      int64
	Query    string
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sc *sessionCtx, name, title, nav string, data any) {
	cfg := s.db.Settings()
	p := page{
		Asset:    assetTag,
		Title:    title,
		Nav:      nav,
		Settings: cfg,
		Instance: cfg.InstanceName,
		Version:  version.Version,
		Now:      time.Now().Unix(),
		Query:    r.URL.RawQuery,
		Data:     data,
	}
	if sc != nil {
		p.Admin = sc.admin
		p.CSRF = sc.session.CSRF
		p.Hints = sc.hints
		p.Flashes = s.takeFlashes(string(sc.session.ID))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	var buf strings.Builder
	if err := s.tmpl.ExecuteTemplate(&buf, name, p); err != nil {
		s.log.Error("render", "template", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(buf.String()))
}

// fail renders a plain error page. It never echoes user input back.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = s.tmpl.ExecuteTemplate(w, "error.html", page{
		Asset:    assetTag,
		Title:    http.StatusText(code),
		Instance: s.db.Settings().InstanceName,
		Version:  version.Version,
		Data:     map[string]any{"Code": code, "Message": msg},
	})
}

// -------------------------------------------------------------------- flashes

func (s *Server) flash(sc *sessionCtx, kind, format string, args ...any) {
	if sc == nil {
		return
	}
	key := string(sc.session.ID)
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	// Opportunistic cleanup: messages are consumed by the next page render, so
	// anything still here after an hour belongs to a session that went away.
	for k, v := range s.flashes {
		if len(v) > 0 && time.Since(v[len(v)-1].At) > time.Hour {
			delete(s.flashes, k)
		}
	}
	s.flashes[key] = append(s.flashes[key], flash{Kind: kind, Text: fmt.Sprintf(format, args...), At: time.Now()})
}

func (s *Server) takeFlashes(key string) []flash {
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	f := s.flashes[key]
	delete(s.flashes, key)
	return f
}

// -------------------------------------------------------------------- helpers

func (s *Server) audit(r *http.Request, sc *sessionCtx, action, target, detail string, ok bool) {
	actor := "system"
	if sc != nil {
		actor = sc.admin.Username
	}
	s.db.Audit(r.Context(), model.AuditEntry{
		Actor: actor, ActorType: "admin", Action: action, Target: target,
		Detail: detail, IP: httpx.ClientIP(r), OK: ok,
	})
}

func pathID(r *http.Request, name string) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func intParam(r *http.Request, name string, def, min, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func formInt(r *http.Request, name string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
	if err != nil {
		return def
	}
	return v
}

func formBool(r *http.Request, name string) bool {
	v := r.PostFormValue(name)
	return v == "1" || v == "on" || v == "true"
}

func notFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
