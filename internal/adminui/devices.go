package adminui

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/rsc"
)

func (s *Server) getDevices(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	devices, err := s.db.ListDevices(r.Context(), q)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	cursor, _ := s.db.Cursor(r.Context())
	blocked, _ := s.db.BlockedCount(r.Context(), true)
	s.render(w, r, sc, "devices.html", "Devices", "devices", map[string]any{
		"Devices": devices,
		"Q":       q,
		"Cursor":  cursor,
		"Blocked": blocked,
		"Defaults": map[string]any{
			"List":    s.db.Settings().DefaultListName,
			"Detect":  s.db.Settings().DefaultDetectList,
			"Timeout": s.db.Settings().DefaultBlockTimeout,
			"Sync":    s.db.Settings().DefaultSyncInterval,
			"Report":  s.db.Settings().DefaultReportInterval,
		},
	})
}

func (s *Server) loadDevice(w http.ResponseWriter, r *http.Request) (model.Device, bool) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad device id")
		return model.Device{}, false
	}
	d, err := s.db.DeviceByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such device")
		return model.Device{}, false
	}
	return d, true
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	tokens, err := s.db.ListTokens(ctx, d.ID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	series, _ := s.db.DeviceSeries(ctx, d.ID, intParam(r, "hours", 48, 6, 720))
	recent, _ := s.db.Activity(ctx, d.ID, 25, 0)
	cursor, _ := s.db.Cursor(ctx)
	s.render(w, r, sc, "device.html", d.Name, "devices", map[string]any{
		"D":       d,
		"Tokens":  tokens,
		"Series":  series,
		"Recent":  recent,
		"Cursor":  cursor,
		"Lag":     cursor - d.Cursor,
		"BaseURL": s.baseURL(r),
	})
}

func (s *Server) postDeviceCreate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	cfg := s.db.Settings()
	d := model.Device{
		Name:           strings.TrimSpace(r.PostFormValue("name")),
		Description:    trunc(300, strings.TrimSpace(r.PostFormValue("description"))),
		ROSBranch:      r.PostFormValue("ros_branch"),
		Enabled:        true,
		ListName:       firstNonEmpty(strings.TrimSpace(r.PostFormValue("list_name")), cfg.DefaultListName),
		DetectList:     firstNonEmpty(strings.TrimSpace(r.PostFormValue("detect_list")), cfg.DefaultDetectList),
		BlockTimeout:   firstNonEmpty(strings.TrimSpace(r.PostFormValue("block_timeout")), cfg.DefaultBlockTimeout),
		SyncInterval:   formInt(r, "sync_interval", cfg.DefaultSyncInterval),
		ReportInterval: formInt(r, "report_interval", cfg.DefaultReportInterval),
		Contribute:     true,
		Consume:        true,
		IPv6:           formBool(r, "ipv6"),
		Tags:           trunc(200, strings.TrimSpace(r.PostFormValue("tags"))),
		CreatedBy:      sc.admin.Username,
	}
	created, err := s.db.CreateDevice(r.Context(), d)
	if err != nil {
		s.audit(r, sc, "device.create", d.Name, err.Error(), false)
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
		return
	}
	s.audit(r, sc, "device.create", created.Name, "", true)
	s.flash(sc, "ok", "Added %s. Generate its script bundle to finish provisioning.", created.Name)
	http.Redirect(w, r, fmt.Sprintf("/devices/%d/scripts", created.ID), http.StatusSeeOther)
}

func (s *Server) postDeviceUpdate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	d.Name = strings.TrimSpace(r.PostFormValue("name"))
	d.Description = trunc(300, strings.TrimSpace(r.PostFormValue("description")))
	d.ROSBranch = r.PostFormValue("ros_branch")
	d.Enabled = formBool(r, "enabled")
	d.ListName = strings.TrimSpace(r.PostFormValue("list_name"))
	d.DetectList = strings.TrimSpace(r.PostFormValue("detect_list"))
	d.BlockTimeout = strings.TrimSpace(r.PostFormValue("block_timeout"))
	d.VerifyCert = r.PostFormValue("verify_cert")
	d.SyncInterval = formInt(r, "sync_interval", d.SyncInterval)
	d.ReportInterval = formInt(r, "report_interval", d.ReportInterval)
	d.Contribute = formBool(r, "contribute")
	d.Consume = formBool(r, "consume")
	d.IPv6 = formBool(r, "ipv6")
	d.Tags = trunc(200, strings.TrimSpace(r.PostFormValue("tags")))
	d.Notes = trunc(1000, strings.TrimSpace(r.PostFormValue("notes")))

	// Validate by generating with a throwaway token: whatever the generator
	// refuses would produce a broken script on the router.
	probe := s.params(d, "apb_validationprobe0000")
	probe.BaseURL = s.baseURL(r)
	if _, err := rsc.Generate(probe); err != nil {
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/devices/%d", d.ID), http.StatusSeeOther)
		return
	}
	if err := s.db.UpdateDevice(r.Context(), d); err != nil {
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/devices/%d", d.ID), http.StatusSeeOther)
		return
	}
	s.audit(r, sc, "device.update", d.Name, "", true)
	s.flash(sc, "ok", "Saved. The router picks up the new settings on its next run, without reinstalling anything.")
	http.Redirect(w, r, fmt.Sprintf("/devices/%d", d.ID), http.StatusSeeOther)
}

func (s *Server) postDeviceDelete(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteDevice(r.Context(), d.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not delete the device")
		return
	}
	s.audit(r, sc, "device.delete", d.Name, "", true)
	s.flash(sc, "ok", "Deleted %s. Its tokens no longer authenticate.", d.Name)
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// ------------------------------------------------------------------- tokens

func (s *Server) postTokenCreate(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	token, prefix, err := s.issueToken(r, sc, d, trunc(60, strings.TrimSpace(r.PostFormValue("label"))), formInt(r, "days", 0))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not issue a token")
		return
	}
	s.flash(sc, "warn", "New token for %s, shown once: %s", d.Name, token)
	s.flash(sc, "ok", "Token %s… is active. Generate a script bundle to install it, or paste it into an existing script.", prefix)
	http.Redirect(w, r, fmt.Sprintf("/devices/%d", d.ID), http.StatusSeeOther)
}

func (s *Server) issueToken(r *http.Request, sc *sessionCtx, d model.Device, label string, days int) (token, prefix string, err error) {
	token, err = auth.NewDeviceToken()
	if err != nil {
		return "", "", err
	}
	var expires int64
	if days > 0 {
		expires = time.Now().AddDate(0, 0, days).Unix()
	}
	prefix = auth.TokenPrefix(token)
	if label == "" {
		label = "issued " + time.Now().UTC().Format("2006-01-02")
	}
	if _, err := s.db.CreateToken(r.Context(), d.ID, prefix, s.keys.TokenHash(token), label, sc.admin.Username, expires); err != nil {
		return "", "", err
	}
	s.audit(r, sc, "device.token_issue", d.Name, prefix, true)
	return token, prefix, nil
}

func (s *Server) postTokenRevoke(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	tid, ok := pathID(r, "tid")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad token id")
		return
	}
	tok, err := s.db.TokenByID(r.Context(), tid)
	if err != nil || tok.DeviceID != d.ID {
		s.fail(w, r, http.StatusNotFound, "no such token")
		return
	}
	if err := s.db.RevokeToken(r.Context(), tid); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not revoke the token")
		return
	}
	s.audit(r, sc, "device.token_revoke", d.Name, tok.Prefix, true)
	s.flash(sc, "ok", "Revoked %s…. Any router still using it stops synchronising immediately.", tok.Prefix)
	http.Redirect(w, r, fmt.Sprintf("/devices/%d", d.ID), http.StatusSeeOther)
}

// ------------------------------------------------------------------ scripts

// getDeviceScripts previews the bundle with the token masked, so an operator
// can read exactly what will run on the router before a credential exists.
func (s *Server) getDeviceScripts(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	const placeholder = "apb_TOKENAPPEARSHEREONDOWNLOAD"
	p := s.params(d, placeholder)
	p.BaseURL = s.baseURL(r)
	bundle, err := rsc.Generate(p)
	data := map[string]any{"D": d, "BaseURL": s.baseURL(r), "Placeholder": placeholder}
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Bundle"] = bundle
	}
	s.render(w, r, sc, "scripts.html", "Scripts for "+d.Name, "devices", data)
}

// postDeviceScripts issues a fresh token and streams the requested file. The
// plaintext token exists only inside this response: it is never stored and
// cannot be downloaded again.
func (s *Server) postDeviceScripts(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	d, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	part := r.PostFormValue("part")
	if part == "firewall" {
		// The firewall example carries no credential, so it needs no token.
		p := s.params(d, "apb_noTokenNeededHere000")
		p.BaseURL = s.baseURL(r)
		bundle, err := rsc.Generate(p)
		if err != nil {
			s.flash(sc, "err", "%s", err.Error())
			http.Redirect(w, r, fmt.Sprintf("/devices/%d/scripts", d.ID), http.StatusSeeOther)
			return
		}
		serveRSC(w, "apb-firewall-example.rsc", bundle.Firewall)
		return
	}
	if part == "uninstall" {
		p := s.params(d, "apb_noTokenNeededHere000")
		p.BaseURL = s.baseURL(r)
		bundle, err := rsc.Generate(p)
		if err != nil {
			s.flash(sc, "err", "%s", err.Error())
			http.Redirect(w, r, fmt.Sprintf("/devices/%d/scripts", d.ID), http.StatusSeeOther)
			return
		}
		serveRSC(w, "apb-uninstall.rsc", bundle.Uninstall)
		return
	}

	token, prefix, err := s.issueToken(r, sc, d, "script bundle", formInt(r, "days", 0))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not issue a token")
		return
	}
	p := s.params(d, token)
	p.BaseURL = s.baseURL(r)
	bundle, err := rsc.Generate(p)
	if err != nil {
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/devices/%d/scripts", d.ID), http.StatusSeeOther)
		return
	}
	var name, body string
	switch part {
	case "scripts":
		name, body = "apb-scripts.rsc", bundle.Scripts
	case "scheduler":
		name, body = "apb-scheduler.rsc", bundle.Scheduler
	default:
		name, body = "apb-install.rsc", bundle.Install
	}
	s.log.Info("script bundle generated", "device", d.Name, "part", part,
		"token_prefix", prefix, "admin", sc.admin.Username)
	serveRSC(w, name, body)
}

func serveRSC(w http.ResponseWriter, name, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(body))
}

// baseURL is the address routers should call. The configured value wins; the
// request host is only a fallback for a first run before it is set.
func (s *Server) baseURL(r *http.Request) string {
	if s.opt.BaseURL != "" {
		return strings.TrimRight(s.opt.BaseURL, "/")
	}
	scheme := "https"
	if r.TLS == nil && !s.opt.SecureOnly {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// params builds generator parameters, allowing a plain HTTP endpoint only when
// the service itself is running in development mode.
func (s *Server) params(d model.Device, token string) rsc.Params {
	cfg := s.db.Settings()
	p := rsc.FromDevice(d, s.opt.BaseURL, cfg.InstanceName, token, cfg.RequireUserAgent)
	p.AllowInsecureURL = !s.opt.SecureOnly
	return p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
