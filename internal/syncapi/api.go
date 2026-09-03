// Package syncapi implements the router-facing protocol.
//
// The wire format is a single comma separated token stream with no trailing
// newline, because that is the one shape RouterOS can decode for free: one
// :toarray call yields an array, and the first character of each token says
// what it is.
//
//	c<seq>   cursor to remember once the rest has been applied
//	+<addr>  add to the blocklist
//	-<addr>  remove from the blocklist
//	m1       more changes are already waiting: poll again immediately
//	r1       cursor too old, run a full resynchronisation
//	n<id>    next page marker during a full resynchronisation
//
// A response is always bounded by the max_sync_bytes setting so it fits inside
// the buffer /tool fetch hands to a script, which truncates well before 64 KB.
//
// Endpoints (all under /api/v1, all requiring a device bearer token):
//
//	POST /report   upload locally detected addresses
//	GET  /sync     fetch the delta since a cursor
//	GET  /full     fetch the current blocklist in pages, after a reboot
//	GET  /whoami   fetch this device's server-side configuration
package syncapi

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/netutil"
	"github.com/alexwoo-awso/apb/internal/store"
)

// API serves the device protocol.
type API struct {
	db      *store.DB
	keys    *auth.Keyring
	log     *slog.Logger
	authLim *httpx.Limiter // unauthenticated attempts, keyed by client address
	devLim  *httpx.Limiter // authenticated traffic, keyed by device
}

// New builds the device API.
func New(db *store.DB, keys *auth.Keyring, log *slog.Logger) *API {
	return &API{
		db:   db,
		keys: keys,
		log:  log,
		// A wrong or missing token is cheap to detect but must not be cheap to
		// grind: ten immediate attempts, then one per two seconds.
		authLim: httpx.NewLimiter(0.5, 10),
		// A device polling every 15s uses ~0.07 req/s; this leaves ample room
		// for catch-up loops while capping a runaway script.
		devLim: httpx.NewLimiter(4, 60),
	}
}

// Routes registers the device endpoints on mux.
func (a *API) Routes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/report", a.authed(a.handleReport))
	mux.Handle("GET /api/v1/sync", a.authed(a.handleSync))
	mux.Handle("GET /api/v1/full", a.authed(a.handleFull))
	mux.Handle("GET /api/v1/whoami", a.authed(a.handleWhoami))
}

type deviceHandler func(http.ResponseWriter, *http.Request, model.Device)

// authed resolves the bearer token, applies the optional User-Agent gate and
// the rate limits, then hands the request to the endpoint.
func (a *API) authed(next deviceHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r)
		s := a.db.Settings()

		if want := s.RequireUserAgent; want != "" && !agentMatches(r, want) {
			// The client is told nothing, so probing for the gate reveals
			// nothing. The operator's log gets both values, because a mismatch
			// here looks exactly like a bad token and is otherwise a guessing
			// game: it happens whenever this setting is changed without
			// regenerating the bundles that were built against the old value.
			a.log.Warn("device request rejected",
				"ip", ip, "reason", "user-agent", "path", r.URL.Path, "want", want,
				"got_agent_header", clip(r.Header.Get(AgentHeader), 120),
				"got_user_agent", clip(strings.Join(r.Header.Values("User-Agent"), " | "), 120),
				"fix", "clear require_user_agent under Settings, or regenerate this device's bundle so it sends the current value")
			w.Header().Set("WWW-Authenticate", `Bearer realm="apb"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		token, ok := bearer(r)
		if !ok {
			a.deny(w, r, ip, "missing token")
			return
		}
		if !a.authLim.Allow(ip) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		device, tokenID, err := a.db.DeviceByTokenHash(r.Context(), a.keys.TokenHash(token))
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				a.log.Error("token lookup", "err", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			a.deny(w, r, ip, "unknown token")
			return
		}
		if !a.devLim.Allow(strconv.FormatInt(device.ID, 10)) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		a.authLim.Reset(ip)
		a.db.TouchToken(r.Context(), tokenID, time.Now().Unix())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, device)
	})
}

func (a *API) deny(w http.ResponseWriter, r *http.Request, ip, reason string) {
	a.log.Warn("device request rejected", "ip", ip, "reason", reason, "path", r.URL.Path)
	w.Header().Set("WWW-Authenticate", `Bearer realm="apb"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// AgentHeader is the dedicated header the generated scripts use to identify
// themselves. It exists because RouterOS sets User-Agent itself and does not
// reliably let a script override it: a v6 router sends "Mikrotik/6.x Fetch"
// whatever the script asks for. A header RouterOS has no opinion about is
// passed through verbatim, so the gate works the same on every version.
const AgentHeader = "X-Apb-Agent"

// agentMatches reports whether the required client identity is present, in the
// dedicated header or in any User-Agent value. Every User-Agent value is
// checked rather than only the first, because a client that appends its own
// identity alongside the one a script asked for must not be rejected for a
// header it did send.
func agentMatches(r *http.Request, want string) bool {
	if r.Header.Get(AgentHeader) == want {
		return true
	}
	for _, got := range r.Header.Values("User-Agent") {
		if got == want {
			return true
		}
	}
	return false
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	t := strings.TrimSpace(h[len(prefix):])
	if t == "" || len(t) > 256 {
		return "", false
	}
	return t, true
}

// ------------------------------------------------------------------- report

func (a *API) handleReport(w http.ResponseWriter, r *http.Request, d model.Device) {
	s := a.db.Settings()
	if !d.Contribute {
		http.Error(w, "err,contribute disabled", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.MaxReportSize)+1))
	if err != nil {
		http.Error(w, "err,read", http.StatusBadRequest)
		return
	}
	if len(body) > s.MaxReportSize {
		http.Error(w, "err,too large", http.StatusRequestEntityTooLarge)
		return
	}

	a.noteIdentity(r, d, r.URL.Query())

	list := netutil.SplitList(string(body))
	now := time.Now().Unix()
	res, err := a.db.Ingest(r.Context(), d.ID, list, now)
	if err != nil {
		a.log.Error("ingest", "device", d.Name, "err", err)
		http.Error(w, "err,server", http.StatusInternalServerError)
		return
	}
	if res.Broadcast > 0 {
		a.log.Info("blocklist grew", "device", d.Name, "new", res.Broadcast, "cursor", res.Cursor)
	}
	fmt.Fprintf(w, "ok,%d,%d,%d,%d,%d,%d",
		res.Accepted, res.NewAddresses, res.Broadcast, res.Whitelisted, res.Invalid, res.Cursor)
}

// noteIdentity records the self-description a router may attach to any call.
// Headers are preferred over query parameters because a MikroTik identity may
// contain spaces, which RouterOS cannot URL-encode on its own.
func (a *API) noteIdentity(r *http.Request, d model.Device, q map[string][]string) {
	get := func(header, param string) string {
		if v := r.Header.Get(header); v != "" {
			return clip(v, 64)
		}
		if v, ok := q[param]; ok && len(v) > 0 {
			return clip(v[0], 64)
		}
		return ""
	}
	identity := get("X-Apb-Identity", "identity")
	ros := get("X-Apb-Ros", "ros")
	board := get("X-Apb-Model", "model")
	if identity == "" && ros == "" && board == "" {
		return
	}
	if err := a.db.RecordIdentity(r.Context(), d.ID, identity, ros, board, httpx.ClientIP(r)); err != nil {
		a.log.Warn("record identity", "device", d.Name, "err", err)
	}
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// --------------------------------------------------------------------- sync

func (a *API) handleSync(w http.ResponseWriter, r *http.Request, d model.Device) {
	s := a.db.Settings()
	q := r.URL.Query()
	cursor, _ := strconv.ParseInt(q.Get("c"), 10, 64)
	if cursor < 0 {
		cursor = 0
	}
	applied := int64(-1)
	if v := q.Get("n"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			applied = n
		}
	}
	now := time.Now().Unix()
	ip := httpx.ClientIP(r)

	if !d.Consume {
		// The router still reports its liveness, it just receives nothing.
		_ = a.db.RecordSync(r.Context(), d.ID, cursor, applied, ip, now)
		latest, _ := a.db.Cursor(r.Context())
		fmt.Fprintf(w, "c%d", latest)
		return
	}

	delta, err := a.db.ChangesSince(r.Context(), cursor, s.MaxSyncBytes)
	if err != nil {
		a.log.Error("changes", "device", d.Name, "err", err)
		http.Error(w, "err,server", http.StatusInternalServerError)
		return
	}
	if err := a.db.RecordSync(r.Context(), d.ID, cursor, applied, ip, now); err != nil {
		a.log.Warn("record sync", "device", d.Name, "err", err)
	}

	if delta.Resync {
		// The router has been away longer than the changelog is retained, so
		// an incremental catch-up is no longer provably complete.
		io.WriteString(w, "r1")
		return
	}

	// The idle case is by far the most common. It answers with the current
	// cursor rather than an empty body: ten bytes, and it lets the router
	// confirm it is in step instead of inferring it from silence. Some
	// RouterOS builds also dislike a zero-length fetch response.
	tokens := make([]string, 0, 4+len(delta.Adds)+len(delta.Removes))
	tokens = append(tokens, "c"+strconv.FormatInt(delta.Cursor, 10))
	if delta.More {
		tokens = append(tokens, "m1")
	}
	for _, s := range filterFamily(delta.Adds, d.IPv6) {
		tokens = append(tokens, "+"+s)
	}
	for _, s := range filterFamily(delta.Removes, d.IPv6) {
		tokens = append(tokens, "-"+s)
	}
	io.WriteString(w, strings.Join(tokens, ","))
}

// --------------------------------------------------------------------- full

func (a *API) handleFull(w http.ResponseWriter, r *http.Request, d model.Device) {
	s := a.db.Settings()
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("a"), 10, 64)
	if after < 0 {
		after = 0
	}
	now := time.Now().Unix()

	var tokens []string
	if after == 0 {
		// The cursor is taken before the snapshot is read. Anything that
		// changes while the pages are being fetched is delivered again by the
		// delta stream, and applying it twice is harmless.
		cursor, err := a.db.Cursor(r.Context())
		if err != nil {
			http.Error(w, "err,server", http.StatusInternalServerError)
			return
		}
		tokens = append(tokens, "c"+strconv.FormatInt(cursor, 10))
		if err := a.db.RecordBootstrap(r.Context(), d.ID, now); err != nil {
			a.log.Warn("record bootstrap", "device", d.Name, "err", err)
		}
		a.log.Info("device bootstrap started", "device", d.Name, "cursor", cursor)
	}
	if !d.Consume {
		io.WriteString(w, strings.Join(tokens, ","))
		return
	}

	ips, next, more, err := a.db.SnapshotPage(r.Context(), after, s.MaxSyncBytes, d.IPv6)
	if err != nil {
		a.log.Error("snapshot", "device", d.Name, "err", err)
		http.Error(w, "err,server", http.StatusInternalServerError)
		return
	}
	if more {
		tokens = append(tokens, "n"+strconv.FormatInt(next, 10))
	}
	for _, s := range ips {
		tokens = append(tokens, "+"+s)
	}
	io.WriteString(w, strings.Join(tokens, ","))
}

// ------------------------------------------------------------------- whoami

// handleWhoami returns the device's server-side configuration as a single
// comma separated line, which a RouterOS script turns into an array with one
// :toarray call. Field order, after the format version:
//
//	1 version, 2 name, 3 list, 4 detect list, 5 timeout, 6 sync interval,
//	7 report interval, 8 ipv6, 9 consume, 10 contribute, 11 cursor,
//	12 blocked count
func (a *API) handleWhoami(w http.ResponseWriter, r *http.Request, d model.Device) {
	a.noteIdentity(r, d, r.URL.Query())
	cursor, _ := a.db.Cursor(r.Context())
	blocked, _ := a.db.BlockedCount(r.Context(), d.IPv6)
	fmt.Fprintf(w, "1,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d",
		csvSafe(d.Name), csvSafe(d.ListName), csvSafe(d.DetectList), csvSafe(d.BlockTimeout),
		d.SyncInterval, d.ReportInterval, boolNum(d.IPv6), boolNum(d.Consume), boolNum(d.Contribute),
		cursor, blocked)
}

// ------------------------------------------------------------------- helpers

// filterFamily drops IPv6 entries for routers that have not enabled them, so a
// v4-only script never sees an address it cannot add.
func filterFamily(items []string, ipv6 bool) []string {
	if ipv6 {
		return items
	}
	out := items[:0:0]
	for _, s := range items {
		if !strings.ContainsRune(s, ':') {
			out = append(out, s)
		}
	}
	return out
}

func csvSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ',' || r == '\n' || r == '\r' {
			return '_'
		}
		return r
	}, s)
}

func boolNum(b bool) int {
	if b {
		return 1
	}
	return 0
}
