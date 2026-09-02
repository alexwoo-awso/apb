package adminui

import (
	"net/http"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/model"
)

// ---------------------------------------------------------------- enrolment

// getEnroll shows the second-factor enrolment page. A secret is minted and
// stored sealed on first visit, and only marked enrolled once the operator has
// proved they can generate a code from it.
func (s *Server) getEnroll(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	secret, err := s.pendingSecret(r, sc)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not prepare two-factor enrolment")
		return
	}
	s.render(w, r, sc, "enroll.html", "Set up two-factor", "", map[string]any{
		"Manual": auth.EncodeTOTPSecret(secret),
		"CSRF":   sc.session.CSRF,
	})
}

func (s *Server) getEnrollQR(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	secret, err := s.pendingSecret(r, sc)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	uri := auth.TOTPURI(s.db.Settings().InstanceName, sc.admin.Username, secret)
	png, err := auth.TOTPQRCodePNG(uri)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// pendingSecret returns the account's not-yet-confirmed secret, creating one
// if this is the first visit.
func (s *Server) pendingSecret(r *http.Request, sc *sessionCtx) ([]byte, error) {
	if len(sc.admin.TOTPSecret) > 0 {
		if secret, err := s.keys.Open(sc.admin.TOTPSecret); err == nil {
			return secret, nil
		}
		// Unreadable, most likely because the server secret was replaced.
		s.log.Warn("discarding unreadable totp secret", "admin", sc.admin.Username)
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := s.keys.Seal(secret)
	if err != nil {
		return nil, err
	}
	if err := s.db.SetTOTP(r.Context(), sc.admin.ID, sealed, false); err != nil {
		return nil, err
	}
	sc.admin.TOTPSecret = sealed
	return secret, nil
}

func (s *Server) postEnroll(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed form submission")
		return
	}
	if !auth.ConstantTimeEqual(r.PostFormValue("csrf"), sc.session.CSRF) {
		s.fail(w, r, http.StatusForbidden, "this form has expired, please reload")
		return
	}
	secret, err := s.pendingSecret(r, sc)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not prepare two-factor enrolment")
		return
	}
	step, err := auth.VerifyTOTP(secret, r.PostFormValue("code"), time.Now())
	if err != nil {
		s.render(w, r, sc, "enroll.html", "Set up two-factor", "", map[string]any{
			"Manual": auth.EncodeTOTPSecret(secret),
			"CSRF":   sc.session.CSRF,
			"Error":  "that code did not match; check the clock on your phone and try the next one",
		})
		return
	}
	s.totpUsed.accept(sc.admin.ID, step)
	if err := s.db.SetTOTP(r.Context(), sc.admin.ID, sc.admin.TOTPSecret, true); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not save the enrolment")
		return
	}
	_ = s.db.NoteLoginSuccess(r.Context(), sc.admin.ID, httpx.ClientIP(r))
	s.audit(r, sc, "account.2fa_enrolled", sc.admin.Username, "", true)
	s.flash(sc, "ok", "Two-factor authentication is now active on your account.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ------------------------------------------------------------------ account

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	sessions, err := s.db.SessionsForAdmin(r.Context(), sc.admin.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	s.render(w, r, sc, "account.html", "Your account", "account", map[string]any{
		"Sessions": sessions,
		"Current":  string(sc.session.ID),
		"MinLen":   auth.MinPasswordLength,
	})
}

func (s *Server) postAccountPassword(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed form submission")
		return
	}
	if !auth.ConstantTimeEqual(r.PostFormValue("csrf"), sc.session.CSRF) {
		s.fail(w, r, http.StatusForbidden, "this form has expired, please reload")
		return
	}
	ctx := r.Context()
	current := r.PostFormValue("current")
	next := r.PostFormValue("password")

	if err := auth.VerifyPassword(sc.admin.PassHash, current); err != nil {
		s.audit(r, sc, "account.password_change", sc.admin.Username, "wrong current password", false)
		s.flash(sc, "err", "Your current password is not correct.")
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if next != r.PostFormValue("password2") {
		s.flash(sc, "err", "The two new passwords do not match.")
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err := auth.CheckPasswordPolicy(next); err != nil {
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not hash the password")
		return
	}
	if err := s.db.SetPassword(ctx, sc.admin.ID, hash, false); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not save the password")
		return
	}
	// Every other session for this account is invalidated, which is the point
	// of changing a password that may have leaked.
	_ = s.db.DeleteSessionsForAdmin(ctx, sc.admin.ID)
	s.audit(r, sc, "account.password_change", sc.admin.Username, "", true)
	s.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// -------------------------------------------------------------------- users

func (s *Server) getUsers(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	admins, err := s.db.ListAdmins(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	s.render(w, r, sc, "users.html", "Administrators", "users", map[string]any{
		"Admins": admins,
		"MinLen": auth.MinPasswordLength,
		"Roles":  []string{model.RoleOwner, model.RoleAdmin, model.RoleViewer},
	})
}

func (s *Server) postUserCreate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	role := r.PostFormValue("role")
	if role == model.RoleOwner && !sc.admin.IsOwner() {
		s.flash(sc, "err", "Only an owner can create another owner.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if role != model.RoleOwner && role != model.RoleAdmin && role != model.RoleViewer {
		role = model.RoleViewer
	}
	password := r.PostFormValue("password")
	if err := auth.CheckPasswordPolicy(password); err != nil {
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not hash the password")
		return
	}
	admin, err := s.db.CreateAdmin(r.Context(), model.Admin{
		Username:           strings.TrimSpace(r.PostFormValue("username")),
		DisplayName:        strings.TrimSpace(r.PostFormValue("display_name")),
		Email:              strings.TrimSpace(r.PostFormValue("email")),
		PassHash:           hash,
		Role:               role,
		MustChangePassword: true,
		CreatedBy:          sc.admin.Username,
	})
	if err != nil {
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	s.audit(r, sc, "user.create", admin.Username, "role="+role, true)
	s.flash(sc, "ok", "Created %s. They will be asked to set up two-factor authentication at first sign in.", admin.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) postUserUpdate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad account id")
		return
	}
	ctx := r.Context()
	target, err := s.db.AdminByID(ctx, id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such account")
		return
	}
	role := r.PostFormValue("role")
	if role != model.RoleOwner && role != model.RoleAdmin && role != model.RoleViewer {
		role = target.Role
	}
	if (role == model.RoleOwner || target.Role == model.RoleOwner) && !sc.admin.IsOwner() {
		s.flash(sc, "err", "Only an owner can change an owner.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	disabled := formBool(r, "disabled")
	if target.Role == model.RoleOwner && (role != model.RoleOwner || disabled) {
		if n, err := s.db.CountOwners(ctx); err == nil && n <= 1 {
			s.flash(sc, "err", "This is the last active owner; promote someone else first.")
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
	}
	if err := s.db.UpdateAdminProfile(ctx, id,
		strings.TrimSpace(r.PostFormValue("display_name")),
		strings.TrimSpace(r.PostFormValue("email")), role, disabled); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not save the account")
		return
	}
	if disabled || role != target.Role {
		// A privilege change must not leave an old session running at the old
		// level, so the account is signed out everywhere.
		_ = s.db.DeleteSessionsForAdmin(ctx, id)
	}
	s.audit(r, sc, "user.update", target.Username, "role="+role, true)
	s.flash(sc, "ok", "Saved %s.", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) postUserDelete(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad account id")
		return
	}
	ctx := r.Context()
	target, err := s.db.AdminByID(ctx, id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such account")
		return
	}
	if target.ID == sc.admin.ID {
		s.flash(sc, "err", "You cannot delete the account you are signed in with.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if target.Role == model.RoleOwner {
		if !sc.admin.IsOwner() {
			s.flash(sc, "err", "Only an owner can delete an owner.")
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
		if n, err := s.db.CountOwners(ctx); err == nil && n <= 1 {
			s.flash(sc, "err", "This is the last owner and cannot be deleted.")
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
	}
	if err := s.db.DeleteAdmin(ctx, id); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not delete the account")
		return
	}
	s.audit(r, sc, "user.delete", target.Username, "", true)
	s.flash(sc, "ok", "Deleted %s.", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) postUserUnlock(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad account id")
		return
	}
	target, err := s.db.AdminByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such account")
		return
	}
	if err := s.db.UnlockAdmin(r.Context(), id); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not unlock the account")
		return
	}
	s.audit(r, sc, "user.unlock", target.Username, "", true)
	s.flash(sc, "ok", "Unlocked %s.", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) postUserReset2FA(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad account id")
		return
	}
	ctx := r.Context()
	target, err := s.db.AdminByID(ctx, id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such account")
		return
	}
	if target.Role == model.RoleOwner && !sc.admin.IsOwner() {
		s.flash(sc, "err", "Only an owner can reset an owner's second factor.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if err := s.db.SetTOTP(ctx, id, nil, false); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not reset the second factor")
		return
	}
	_ = s.db.DeleteSessionsForAdmin(ctx, id)
	s.audit(r, sc, "user.reset_2fa", target.Username, "", true)
	s.flash(sc, "warn", "Cleared the second factor for %s. They will enrol a new authenticator at their next sign in.", target.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) postUserSessions(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad account id")
		return
	}
	target, err := s.db.AdminByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such account")
		return
	}
	if err := s.db.DeleteSessionsForAdmin(r.Context(), id); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not revoke the sessions")
		return
	}
	s.audit(r, sc, "user.revoke_sessions", target.Username, "", true)
	s.flash(sc, "ok", "Signed %s out everywhere.", target.Username)
	if target.ID == sc.admin.ID {
		s.clearCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
