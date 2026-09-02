package adminui

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/store"
)

const cookieName = "apb_session"

// usedTOTP remembers the last accepted one-time-password step per account, so
// a code observed over the operator's shoulder cannot be replayed during the
// 90 seconds it stays arithmetically valid.
type usedTOTP struct {
	mu   sync.Mutex
	last map[int64]uint64
}

func (u *usedTOTP) accept(adminID int64, step uint64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.last == nil {
		u.last = map[int64]uint64{}
	}
	if prev, ok := u.last[adminID]; ok && step <= prev {
		return false
	}
	u.last[adminID] = step
	return true
}

func (s *Server) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.opt.SecureOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) { s.setCookie(w, "", -1) }

// ---------------------------------------------------------------- first run

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.db.CountAdmins(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "setup.html", "First run", "", map[string]any{
		"NeedCode": s.SetupCode != "",
		"MinLen":   auth.MinPasswordLength,
	})
}

func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.db.CountAdmins(ctx)
	if err != nil || n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed form submission")
		return
	}
	ip := httpx.ClientIP(r)
	if !s.loginLim.Allow("setup:" + ip) {
		s.fail(w, r, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}

	fail := func(msg string) {
		s.db.Audit(ctx, model.AuditEntry{Actor: "setup", ActorType: "system",
			Action: "setup.failed", Detail: msg, IP: ip, OK: false})
		s.render(w, r, nil, "setup.html", "First run", "", map[string]any{
			"NeedCode": s.SetupCode != "",
			"MinLen":   auth.MinPasswordLength,
			"Error":    msg,
			"Username": r.PostFormValue("username"),
		})
	}

	if s.SetupCode != "" && !auth.ConstantTimeEqual(strings.TrimSpace(r.PostFormValue("code")), s.SetupCode) {
		fail("that setup code is not correct; it was printed in the server log at startup")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	if username == "" || len(username) > 64 {
		fail("choose a username of 1 to 64 characters")
		return
	}
	password := r.PostFormValue("password")
	if password != r.PostFormValue("password2") {
		fail("the two passwords do not match")
		return
	}
	if err := auth.CheckPasswordPolicy(password); err != nil {
		fail(err.Error())
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fail("could not hash the password")
		return
	}
	admin, err := s.db.CreateAdmin(ctx, model.Admin{
		Username:    username,
		DisplayName: strings.TrimSpace(r.PostFormValue("display_name")),
		Email:       strings.TrimSpace(r.PostFormValue("email")),
		PassHash:    hash,
		Role:        model.RoleOwner,
		CreatedBy:   "setup",
	})
	if err != nil {
		fail(err.Error())
		return
	}
	s.SetupCode = "" // one use only
	s.db.Audit(ctx, model.AuditEntry{Actor: username, ActorType: "admin",
		Action: "setup.completed", Target: username, IP: ip, OK: true})
	s.log.Info("first administrator created", "username", username, "ip", ip)

	if err := s.startSession(w, r, admin, false); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not start a session")
		return
	}
	http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
}

// -------------------------------------------------------------------- login

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if n, err := s.db.CountAdmins(r.Context()); err == nil && n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "login.html", "Sign in", "", map[string]any{
		"Next": safeNext(r.URL.Query().Get("next")),
	})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed form submission")
		return
	}
	ip := httpx.ClientIP(r)
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))

	// The same message for every failure, so probing cannot tell a wrong
	// username from a wrong password from a locked account.
	const generic = "incorrect username, password or the account is locked"
	reject := func(reason string) {
		s.log.Warn("login rejected", "username", username, "ip", ip, "reason", reason)
		s.db.Audit(ctx, model.AuditEntry{Actor: username, ActorType: "admin",
			Action: "login.failed", Detail: reason, IP: ip, OK: false})
		s.render(w, r, nil, "login.html", "Sign in", "", map[string]any{
			"Error": generic, "Username": username, "Next": next,
		})
	}

	if !s.loginLim.Allow("ip:"+ip) || !s.loginLim.Allow("user:"+strings.ToLower(username)) {
		s.render(w, r, nil, "login.html", "Sign in", "", map[string]any{
			"Error": "too many attempts from here; wait a minute and try again",
			"Next":  next,
		})
		return
	}

	admin, err := s.db.AdminByUsername(ctx, username)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusInternalServerError, "database unavailable")
			return
		}
		// Spend comparable time on an unknown user so the response time does
		// not reveal whether the account exists.
		_ = auth.VerifyPassword(dummyHash, password)
		reject("unknown user")
		return
	}
	now := time.Now().Unix()
	if admin.Disabled {
		reject("disabled")
		return
	}
	if admin.LockedUntil > now {
		reject("locked")
		return
	}
	if err := auth.VerifyPassword(admin.PassHash, password); err != nil {
		_ = s.db.NoteLoginFailure(ctx, admin.ID)
		reject("bad password")
		return
	}

	if err := s.startSession(w, r, admin, admin.TOTPEnrolled); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not start a session")
		return
	}
	s.loginLim.Reset("ip:" + ip)
	s.loginLim.Reset("user:" + strings.ToLower(username))

	if admin.TOTPEnrolled {
		dest := "/login/2fa"
		if next != "" {
			dest += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
}

// dummyHash is a real argon2id hash of a random value, compared against when
// the username does not exist so both paths cost the same.
const dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$aG93ZXZlcnRoaXNpc25vdGFyZWFsaGFzaHZhbHVl"

func (s *Server) getLoginTOTP(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.resolve(w, r)
	if !ok {
		return
	}
	if !sc.session.PendingTOTP {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "totp.html", "Two-factor", "", map[string]any{
		"CSRF": sc.session.CSRF,
		"Next": safeNext(r.URL.Query().Get("next")),
	})
}

func (s *Server) postLoginTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, ok := s.resolve(w, r)
	if !ok {
		return
	}
	if !sc.session.PendingTOTP {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed form submission")
		return
	}
	if !auth.ConstantTimeEqual(r.PostFormValue("csrf"), sc.session.CSRF) {
		s.fail(w, r, http.StatusForbidden, "this form has expired, please sign in again")
		return
	}
	ip := httpx.ClientIP(r)
	next := safeNext(r.PostFormValue("next"))

	bad := func(reason string) {
		s.db.Audit(ctx, model.AuditEntry{Actor: sc.admin.Username, ActorType: "admin",
			Action: "login.2fa_failed", Detail: reason, IP: ip, OK: false})
		s.render(w, r, nil, "totp.html", "Two-factor", "", map[string]any{
			"CSRF": sc.session.CSRF, "Next": next,
			"Error": "that code is not valid",
		})
	}
	if !s.loginLim.Allow("totp:" + sc.admin.Username) {
		bad("rate limited")
		return
	}
	secret, err := s.keys.Open(sc.admin.TOTPSecret)
	if err != nil {
		s.log.Error("totp secret unreadable", "admin", sc.admin.Username, "err", err)
		bad("secret unreadable")
		return
	}
	step, err := auth.VerifyTOTP(secret, r.PostFormValue("code"), time.Now())
	if err != nil {
		_ = s.db.NoteLoginFailure(ctx, sc.admin.ID)
		bad("wrong code")
		return
	}
	if !s.totpUsed.accept(sc.admin.ID, step) {
		bad("code already used")
		return
	}

	if err := s.db.PromoteSession(ctx, sc.session.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not complete sign in")
		return
	}
	_ = s.db.NoteLoginSuccess(ctx, sc.admin.ID, ip)
	s.db.Audit(ctx, model.AuditEntry{Actor: sc.admin.Username, ActorType: "admin",
		Action: "login.success", IP: ip, OK: true})
	s.log.Info("signed in", "admin", sc.admin.Username, "ip", ip)

	if sc.admin.MustChangePassword {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		id := s.keys.SessionHash(c.Value)
		if sess, err := s.db.Session(r.Context(), id, 0); err == nil {
			if admin, err := s.db.AdminByID(r.Context(), sess.AdminID); err == nil {
				s.db.Audit(r.Context(), model.AuditEntry{Actor: admin.Username, ActorType: "admin",
					Action: "logout", IP: httpx.ClientIP(r), OK: true})
			}
		}
		_ = s.db.DeleteSession(r.Context(), id)
	}
	s.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// startSession issues a fresh session cookie. The identifier is regenerated on
// every sign in, so a session fixed before authentication is worthless.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, admin model.Admin, pending bool) error {
	value, err := auth.NewSessionValue()
	if err != nil {
		return err
	}
	csrf, err := auth.NewCSRFToken()
	if err != nil {
		return err
	}
	cfg := s.db.Settings()
	now := time.Now()
	sess := model.Session{
		ID:          s.keys.SessionHash(value),
		AdminID:     admin.ID,
		CSRF:        csrf,
		PendingTOTP: pending,
		CreatedAt:   now.Unix(),
		LastSeenAt:  now.Unix(),
		ExpiresAt:   now.Add(time.Duration(cfg.SessionMaxHours) * time.Hour).Unix(),
		IP:          httpx.ClientIP(r),
		UserAgent:   trunc(200, r.UserAgent()),
	}
	if err := s.db.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	s.setCookie(w, value, cfg.SessionMaxHours*3600)
	return nil
}

// safeNext keeps post-login redirects inside this site.
func safeNext(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return ""
	}
	if strings.ContainsAny(v, "\r\n") {
		return ""
	}
	return v
}
