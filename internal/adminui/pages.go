package adminui

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/netutil"
	"github.com/alexwoo-awso/apb/internal/store"
)

// ---------------------------------------------------------------- dashboard

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	hours := intParam(r, "hours", 48, 6, 24*30)
	dash, err := s.db.Dashboard(r.Context(), hours)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	countries, err := s.db.CountryMap(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	geoCountry, geoASN := s.geo.Ready()
	s.render(w, r, sc, "dashboard.html", "Dashboard", "dashboard", map[string]any{
		"D":         dash,
		"Hours":     hours,
		"Map":       choropleth(countries),
		"Countries": countries,
		"GeoReady":  geoCountry || geoASN,
	})
}

// ---------------------------------------------------------------- blocklist

func addressFilterFrom(r *http.Request) store.AddressFilter {
	q := r.URL.Query()
	f := store.AddressFilter{
		Query:    strings.TrimSpace(q.Get("q")),
		State:    q.Get("state"),
		Country:  strings.ToUpper(strings.TrimSpace(q.Get("cc"))),
		Sort:     q.Get("sort"),
		Limit:    intParam(r, "n", 50, 10, 500),
		MinPeers: int64(intParam(r, "peers", 0, 0, 1000)),
		MinHits:  int64(intParam(r, "hits", 0, 0, 100000)),
	}
	if f.State != model.StateBlocked && f.State != model.StateReleased {
		f.State = model.StateBlocked
	}
	if q.Get("state") == "all" {
		f.State = ""
	}
	if v := q.Get("asn"); v != "" {
		f.ASN, _ = strconv.ParseInt(strings.TrimPrefix(strings.ToUpper(v), "AS"), 10, 64)
	}
	switch q.Get("family") {
	case "4":
		f.Family = 4
	case "6":
		f.Family = 6
	}
	if d := intParam(r, "days", 0, 0, 3650); d > 0 {
		f.Since = time.Now().AddDate(0, 0, -d).Unix()
	}
	f.Offset = intParam(r, "page", 1, 1, 100000) - 1
	f.Offset *= f.Limit
	return f
}

func (s *Server) getAddresses(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	f := addressFilterFrom(r)
	rows, total, err := s.db.ListAddresses(r.Context(), f)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	page := f.Offset/f.Limit + 1
	pages := int((total + int64(f.Limit) - 1) / int64(f.Limit))
	s.render(w, r, sc, "addresses.html", "Blocklist", "addresses", map[string]any{
		"Rows":   rows,
		"Total":  total,
		"Page":   page,
		"Pages":  pages,
		"Filter": f,
		"Params": r.URL.Query(),
	})
}

func (s *Server) getAddress(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad address id")
		return
	}
	addr, err := s.db.AddressByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such address")
		return
	}
	reports, err := s.db.ReportsFor(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	s.render(w, r, sc, "address.html", addr.IP, "addresses", map[string]any{
		"A":       addr,
		"Reports": reports,
	})
}

func (s *Server) postAddressAdd(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	raw := netutil.SplitList(r.PostFormValue("addresses"))
	notes := strings.TrimSpace(r.PostFormValue("notes"))
	var expires int64
	if d := formInt(r, "days", 0); d > 0 {
		expires = time.Now().AddDate(0, 0, d).Unix()
	}
	var added, failed int
	var lastErr string
	for _, ip := range raw {
		if _, err := s.db.BlockManual(r.Context(), ip, sc.admin.Username, notes, expires); err != nil {
			failed++
			lastErr = err.Error()
			continue
		}
		added++
	}
	s.audit(r, sc, "address.block_manual", fmt.Sprintf("%d addresses", added), notes, failed == 0)
	if added > 0 {
		s.flash(sc, "ok", "Blocked %d address(es); the routers will pick them up on their next poll.", added)
	}
	if failed > 0 {
		s.flash(sc, "err", "%d rejected. Last reason: %s", failed, lastErr)
	}
	http.Redirect(w, r, "/addresses", http.StatusSeeOther)
}

func (s *Server) postAddressAction(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	ctx := r.Context()
	action := r.PostFormValue("action")
	back := safeNext(r.PostFormValue("back"))
	if back == "" {
		back = "/addresses"
	}

	var ids []int64
	if r.PostFormValue("scope") == "filter" {
		// "Apply to everything that matches" reuses the exact filter the table
		// was rendered with, so what happens is what the operator was looking
		// at. The filter travels in the return URL the form carries.
		u, err := url.Parse(back)
		if err != nil {
			s.fail(w, r, http.StatusBadRequest, "could not read the current filter")
			return
		}
		f := addressFilterFrom(&http.Request{URL: u, Method: http.MethodGet})
		f.Limit, f.Offset = 0, 0
		ids, err = s.db.IDsForFilter(ctx, f, 100000)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "database unavailable")
			return
		}
	} else {
		for _, v := range r.PostForm["id"] {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				ids = append(ids, n)
			}
		}
	}
	if len(ids) == 0 {
		s.flash(sc, "warn", "Nothing was selected.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	switch action {
	case "release":
		n, err := s.db.Release(ctx, ids, "released by "+sc.admin.Username)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "could not release those addresses")
			return
		}
		s.audit(r, sc, "address.release", fmt.Sprintf("%d addresses", n), "", true)
		s.flash(sc, "ok", "Released %d address(es). Every router drops them within one poll interval.", n)

	case "reblock":
		n, err := s.db.Reblock(ctx, ids)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "could not re-block those addresses")
			return
		}
		s.audit(r, sc, "address.reblock", fmt.Sprintf("%d addresses", n), "", true)
		s.flash(sc, "ok", "Re-blocked %d address(es).", n)

	case "delete":
		n, err := s.db.Delete(ctx, ids)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, "could not delete those addresses")
			return
		}
		s.audit(r, sc, "address.delete", fmt.Sprintf("%d addresses", n), "", true)
		s.flash(sc, "ok", "Deleted %d address(es) and their history.", n)

	case "whitelist":
		reason := strings.TrimSpace(r.PostFormValue("reason"))
		if reason == "" {
			reason = "whitelisted from the blocklist view by " + sc.admin.Username
		}
		var done, failed int
		for _, id := range ids {
			a, err := s.db.AddressByID(ctx, id)
			if err != nil {
				failed++
				continue
			}
			if _, _, err := s.db.AddWhitelist(ctx, a.IP, reason, sc.admin.Username, 0); err != nil {
				failed++
				continue
			}
			done++
		}
		s.audit(r, sc, "address.whitelist", fmt.Sprintf("%d addresses", done), reason, failed == 0)
		s.flash(sc, "ok", "Whitelisted %d address(es).", done)
		if failed > 0 {
			s.flash(sc, "warn", "%d could not be whitelisted.", failed)
		}

	case "extend":
		var expires int64
		if d := formInt(r, "days", 0); d > 0 {
			expires = time.Now().AddDate(0, 0, d).Unix()
		}
		if err := s.db.SetExpiry(ctx, ids, expires); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "could not change the expiry")
			return
		}
		s.audit(r, sc, "address.set_expiry", fmt.Sprintf("%d addresses", len(ids)), model.Stamp(expires), true)
		if expires == 0 {
			s.flash(sc, "ok", "%d address(es) will now never expire.", len(ids))
		} else {
			s.flash(sc, "ok", "%d address(es) now expire on %s.", len(ids), model.Stamp(expires))
		}

	default:
		s.flash(sc, "err", "Unknown action.")
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) postAddressNotes(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad address id")
		return
	}
	notes := trunc(500, strings.TrimSpace(r.PostFormValue("notes")))
	if err := s.db.SetNotes(r.Context(), id, notes); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not save the note")
		return
	}
	s.audit(r, sc, "address.note", strconv.FormatInt(id, 10), notes, true)
	s.flash(sc, "ok", "Note saved.")
	http.Redirect(w, r, fmt.Sprintf("/addresses/%d", id), http.StatusSeeOther)
}

// getAddressExport streams the current filter as CSV or as a plain address
// list, the latter being directly usable by other firewalls.
func (s *Server) getAddressExport(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	f := addressFilterFrom(r)
	f.Limit, f.Offset = 100000, 0
	rows, _, err := s.db.ListAddresses(r.Context(), f)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")

	if r.URL.Query().Get("format") == "txt" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="apb-blocklist-`+stamp+`.txt"`)
		for _, a := range rows {
			fmt.Fprintln(w, a.IP)
		}
		s.audit(r, sc, "address.export", fmt.Sprintf("%d rows", len(rows)), "txt", true)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="apb-blocklist-`+stamp+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"address", "family", "state", "first_seen", "last_seen",
		"reports", "routers", "country", "country_name", "asn", "asn_org", "expires_at", "source", "notes"})
	for _, a := range rows {
		_ = cw.Write([]string{
			a.IP, strconv.Itoa(a.Family), a.State, model.Stamp(a.FirstSeen), model.Stamp(a.LastSeen),
			strconv.FormatInt(a.ReportCount, 10), strconv.FormatInt(a.DeviceCount, 10),
			a.Country, a.CountryName, strconv.FormatInt(a.ASN, 10), a.ASNOrg,
			model.Stamp(a.ExpiresAt), a.Source, a.Notes,
		})
	}
	cw.Flush()
	s.audit(r, sc, "address.export", fmt.Sprintf("%d rows", len(rows)), "csv", true)
}

// ---------------------------------------------------------------- whitelist

func (s *Server) getWhitelist(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := intParam(r, "n", 100, 10, 500)
	page := intParam(r, "page", 1, 1, 100000)
	rows, total, err := s.db.ListWhitelist(r.Context(), q, limit, (page-1)*limit)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	s.render(w, r, sc, "whitelist.html", "Whitelist", "whitelist", map[string]any{
		"Rows":  rows,
		"Total": total,
		"Page":  page,
		"Pages": int((total + int64(limit) - 1) / int64(limit)),
		"Q":     q,
	})
}

func (s *Server) getWhitelistPreview(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	cidr := strings.TrimSpace(r.URL.Query().Get("cidr"))
	data := map[string]any{"CIDR": cidr}
	if cidr != "" {
		p, err := s.db.PreviewWhitelist(r.Context(), cidr)
		if err != nil {
			data["Error"] = err.Error()
		} else {
			data["Preview"] = p
		}
	}
	s.render(w, r, sc, "whitelist_preview.html", "Whitelist preview", "whitelist", data)
}

func (s *Server) postWhitelistAdd(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	cidr := strings.TrimSpace(r.PostFormValue("cidr"))
	reason := trunc(300, strings.TrimSpace(r.PostFormValue("reason")))
	var expires int64
	if d := formInt(r, "days", 0); d > 0 {
		expires = time.Now().AddDate(0, 0, d).Unix()
	}
	entry, released, err := s.db.AddWhitelist(r.Context(), cidr, reason, sc.admin.Username, expires)
	if err != nil {
		s.audit(r, sc, "whitelist.add", cidr, err.Error(), false)
		s.flash(sc, "err", "%s", err.Error())
		http.Redirect(w, r, "/whitelist", http.StatusSeeOther)
		return
	}
	s.audit(r, sc, "whitelist.add", entry.CIDR, fmt.Sprintf("released %d", released), true)
	s.flash(sc, "ok", "Whitelisted %s and released %d blocked address(es).", entry.CIDR, released)
	http.Redirect(w, r, "/whitelist", http.StatusSeeOther)
}

func (s *Server) postWhitelistDelete(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "bad rule id")
		return
	}
	cidr, err := s.db.RemoveWhitelist(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no such rule")
		return
	}
	s.audit(r, sc, "whitelist.remove", cidr, "", true)
	s.flash(sc, "ok", "Removed %s. Addresses it released stay released until they are reported again.", cidr)
	http.Redirect(w, r, "/whitelist", http.StatusSeeOther)
}

// ----------------------------------------------------------------- activity

func (s *Server) getActivity(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	limit := intParam(r, "n", 100, 10, 500)
	page := intParam(r, "page", 1, 1, 10000)
	deviceID := int64(intParam(r, "device", 0, 0, 1<<30))
	rows, err := s.db.Activity(r.Context(), deviceID, limit, (page-1)*limit)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	devices, _ := s.db.ListDevices(r.Context(), "")
	changes, _ := s.db.RecentChanges(r.Context(), 50)
	s.render(w, r, sc, "activity.html", "Activity", "activity", map[string]any{
		"Rows":     rows,
		"Devices":  devices,
		"DeviceID": deviceID,
		"Page":     page,
		"Limit":    limit,
		"Changes":  changes,
	})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := intParam(r, "n", 100, 10, 500)
	page := intParam(r, "page", 1, 1, 10000)
	rows, total, err := s.db.ListAudit(r.Context(), q, limit, (page-1)*limit)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "database unavailable")
		return
	}
	s.render(w, r, sc, "audit.html", "Audit log", "audit", map[string]any{
		"Rows":  rows,
		"Total": total,
		"Page":  page,
		"Pages": int((total + int64(limit) - 1) / int64(limit)),
		"Q":     q,
	})
}
