// Package test exercises the whole service the way it actually runs: one mux
// carrying both the router API and the console, backed by a real SQLite file.
package test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alexwoo-awso/apb/internal/adminui"
	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/geo"
	"github.com/alexwoo-awso/apb/internal/httpx"
	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/store"
	"github.com/alexwoo-awso/apb/internal/syncapi"
)

// testLogWriter sends server logs to stderr when APB_TEST_LOG is set, which is
// how a template or query failure inside a handler is diagnosed.
func testLogWriter() io.Writer {
	if os.Getenv("APB_TEST_LOG") != "" {
		return os.Stderr
	}
	return io.Discard
}

type harness struct {
	t       *testing.T
	db      *store.DB
	keys    *auth.Keyring
	srv     *httptest.Server
	admin   model.Admin
	cookie  string
	csrf    string
	device  model.Device
	token   string
	console *adminui.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(testLogWriter(), nil))

	db, err := store.Open(filepath.Join(dir, "apb.db"), log)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	keys, err := auth.NewKeyring(master)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	resolver := geo.New(filepath.Join(dir, "geo"), log)
	t.Cleanup(resolver.Close)

	console, err := adminui.New(db, keys, resolver, adminui.Options{
		BaseURL: "https://apb.example.org", SecureOnly: false, Log: log,
	})
	if err != nil {
		t.Fatalf("console: %v", err)
	}
	api := syncapi.New(db, keys, log)

	mux := http.NewServeMux()
	api.Routes(mux)
	console.Routes(mux)

	srv := httptest.NewServer(httpx.Chain(mux,
		httpx.Recover(log),
		httpx.RealIP(false, ""),
		httpx.SecurityHeaders(false),
	))
	t.Cleanup(srv.Close)

	h := &harness{t: t, db: db, keys: keys, srv: srv, console: console}
	h.seedAdmin()
	h.seedDevice()
	return h
}

// seedAdmin creates a fully enrolled owner and a live session, skipping the
// interactive password and TOTP steps those flows have their own tests for.
func (h *harness) seedAdmin() {
	ctx := h.t.Context()
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		h.t.Fatal(err)
	}
	admin, err := h.db.CreateAdmin(ctx, model.Admin{
		Username: "tester", PassHash: hash, Role: model.RoleOwner,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	secret, _ := auth.NewTOTPSecret()
	sealed, _ := h.keys.Seal(secret)
	if err := h.db.SetTOTP(ctx, admin.ID, sealed, true); err != nil {
		h.t.Fatal(err)
	}
	admin.TOTPEnrolled = true
	h.admin = admin

	value, _ := auth.NewSessionValue()
	csrf, _ := auth.NewCSRFToken()
	now := time.Now()
	if err := h.db.CreateSession(ctx, model.Session{
		ID: h.keys.SessionHash(value), AdminID: admin.ID, CSRF: csrf,
		CreatedAt: now.Unix(), LastSeenAt: now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), IP: "203.0.113.9",
	}); err != nil {
		h.t.Fatal(err)
	}
	h.cookie = value
	h.csrf = csrf
}

func (h *harness) seedDevice() {
	ctx := h.t.Context()
	d, err := h.db.CreateDevice(ctx, model.Device{
		Name: "edge-1", ROSBranch: "v7", Enabled: true, Contribute: true, Consume: true,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.device = d

	token, err := auth.NewDeviceToken()
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.db.CreateToken(ctx, d.ID, auth.TokenPrefix(token), h.keys.TokenHash(token),
		"test", "test", 0); err != nil {
		h.t.Fatal(err)
	}
	h.token = token
}

// ----------------------------------------------------------------- requests

func (h *harness) api(method, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: "apb_session", Value: h.cookie})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *harness) post(path string, form url.Values) (int, string) {
	h.t.Helper()
	form.Set("csrf", h.csrf)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "apb_session", Value: h.cookie})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// -------------------------------------------------------------------- tests

// TestReportToSyncRoundTrip is the core promise of the service: an address one
// router reports reaches every other router through the delta stream, and a
// release takes it away again.
func TestReportToSyncRoundTrip(t *testing.T) {
	h := newHarness(t)

	code, body := h.api(http.MethodGet, "/api/v1/sync?c=0", "")
	if code != http.StatusOK {
		t.Fatalf("initial sync: %d %s", code, body)
	}
	if !strings.HasPrefix(body, "c") {
		t.Fatalf("initial sync should return a cursor, got %q", body)
	}

	code, body = h.api(http.MethodPost, "/api/v1/report", "203.0.113.7,198.51.100.4,'')(*&^,192.168.1.1")
	if code != http.StatusOK {
		t.Fatalf("report: %d %s", code, body)
	}
	// 198.51.100.0/24 and 203.0.113.0/24 are documentation ranges and rejected
	// as bogons, so use routable addresses for the real assertions.
	code, body = h.api(http.MethodPost, "/api/v1/report", "45.83.64.7, 91.240.118.3")
	if code != http.StatusOK || !strings.HasPrefix(body, "ok,") {
		t.Fatalf("report: %d %s", code, body)
	}
	fields := strings.Split(body, ",")
	if fields[1] != "2" {
		t.Errorf("expected 2 accepted, got %q", body)
	}
	if fields[3] != "2" {
		t.Errorf("expected 2 broadcast, got %q", body)
	}

	code, body = h.api(http.MethodGet, "/api/v1/sync?c=0", "")
	if code != http.StatusOK {
		t.Fatalf("sync: %d", code)
	}
	if !strings.Contains(body, "+45.83.64.7") || !strings.Contains(body, "91.240.118.3") {
		t.Fatalf("delta missing the reported addresses: %q", body)
	}
	if strings.Contains(body, "\n") {
		t.Errorf("the wire format must be one line with no trailing newline: %q", body)
	}

	cursor := cursorOf(t, body)

	// Nothing new: the router gets its cursor back and nothing else.
	code, body = h.api(http.MethodGet, "/api/v1/sync?c="+strconv.FormatInt(cursor, 10), "")
	if code != http.StatusOK {
		t.Fatalf("idle sync: %d", code)
	}
	if strings.ContainsAny(body, "+-") {
		t.Errorf("idle sync should carry no operations, got %q", body)
	}

	// Releasing from the console must reach the router as a removal.
	a, err := h.db.AddressByIP(t.Context(), "45.83.64.7")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Release(t.Context(), []int64{a.ID}, "test"); err != nil {
		t.Fatal(err)
	}
	code, body = h.api(http.MethodGet, "/api/v1/sync?c="+strconv.FormatInt(cursor, 10), "")
	if code != http.StatusOK || !strings.Contains(body, "-45.83.64.7") {
		t.Fatalf("release did not propagate: %d %q", code, body)
	}
}

// TestFullResyncRebuildsTheList covers the after-a-reboot path: no cursor, so
// the router downloads the whole list in pages and adopts the cursor taken
// before the first page.
func TestFullResyncRebuildsTheList(t *testing.T) {
	h := newHarness(t)

	var addrs []string
	for i := 1; i <= 400; i++ {
		addrs = append(addrs, "45.83."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256))
	}
	if code, body := h.api(http.MethodPost, "/api/v1/report", strings.Join(addrs, ",")); code != http.StatusOK {
		t.Fatalf("seed report: %d %s", code, body)
	}

	seen := map[string]bool{}
	var cursor int64
	after := ""
	for page := 0; page < 50; page++ {
		path := "/api/v1/full"
		if after != "" {
			path += "?a=" + after
		}
		code, body := h.api(http.MethodGet, path, "")
		if code != http.StatusOK {
			t.Fatalf("full page %d: %d", page, code)
		}
		if len(body) > 8192 {
			t.Fatalf("page %d is %d bytes, above the fetch buffer budget", page, len(body))
		}
		after = ""
		for _, tok := range strings.Split(body, ",") {
			if len(tok) < 2 {
				continue
			}
			switch tok[0] {
			case '+':
				seen[tok[1:]] = true
			case 'c':
				cursor, _ = strconv.ParseInt(tok[1:], 10, 64)
			case 'n':
				after = tok[1:]
			}
		}
		if after == "" {
			break
		}
	}
	if cursor == 0 {
		t.Error("full resync did not hand out a cursor")
	}
	blocked, _ := h.db.BlockedCount(t.Context(), false)
	if int64(len(seen)) != blocked {
		t.Errorf("full resync returned %d addresses, database holds %d", len(seen), blocked)
	}
}

// TestWhitelistReleasesAndBlocks is the second half of requirement two: an
// address that turns up on the whitelist has to be withdrawn from the routers.
func TestWhitelistReleasesAndBlocks(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()

	if code, _ := h.api(http.MethodPost, "/api/v1/report", "45.83.64.7,45.83.64.8"); code != http.StatusOK {
		t.Fatal("report failed")
	}
	code, body := h.api(http.MethodGet, "/api/v1/sync?c=0", "")
	cursor := cursorOf(t, body)
	if code != http.StatusOK {
		t.Fatal("sync failed")
	}

	entry, released, err := h.db.AddWhitelist(ctx, "45.83.64.0/24", "test range", "tester", 0)
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	if entry.CIDR != "45.83.64.0/24" {
		t.Errorf("cidr not canonicalised: %s", entry.CIDR)
	}
	if released != 2 {
		t.Errorf("expected 2 released, got %d", released)
	}

	code, body = h.api(http.MethodGet, "/api/v1/sync?c="+strconv.FormatInt(cursor, 10), "")
	if code != http.StatusOK {
		t.Fatalf("sync: %d", code)
	}
	if !strings.Contains(body, "-45.83.64.7") || !strings.Contains(body, "-45.83.64.8") {
		t.Fatalf("whitelisting did not withdraw the addresses: %q", body)
	}

	// A whitelisted address reported again must not come back.
	if code, body := h.api(http.MethodPost, "/api/v1/report", "45.83.64.7"); code != http.StatusOK {
		t.Fatalf("report: %d %s", code, body)
	} else if !strings.HasSuffix(strings.Split(body, ",")[4], "1") {
		t.Errorf("expected the report to be counted as whitelisted: %q", body)
	}
	if _, err := h.db.AddressByIP(ctx, "45.83.64.7"); err == nil {
		if a, _ := h.db.AddressByIP(ctx, "45.83.64.7"); a.State == model.StateBlocked {
			t.Error("a whitelisted address was blocked again")
		}
	}
}

func TestAuthenticationIsRequired(t *testing.T) {
	h := newHarness(t)

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/sync?c=0", nil)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/sync?c=0", nil)
	req.Header.Set("Authorization", "Bearer apb_notarealtokenatall")
	resp, err = h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token: expected 401, got %d", resp.StatusCode)
	}

	// A revoked token stops working immediately.
	tokens, _ := h.db.ListTokens(t.Context(), h.device.ID)
	if err := h.db.RevokeToken(t.Context(), tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.api(http.MethodGet, "/api/v1/sync?c=0", ""); code != http.StatusUnauthorized {
		t.Errorf("revoked token: expected 401, got %d", code)
	}
}

func TestConsoleRequiresASession(t *testing.T) {
	h := newHarness(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for _, path := range []string{"/", "/addresses", "/devices", "/settings", "/users", "/audit"} {
		resp, err := client.Get(h.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s without a session: expected a redirect, got %d", path, resp.StatusCode)
		}
	}
}

// TestEveryConsolePageRenders walks the console so a broken template fails the
// build rather than a page load in production.
func TestEveryConsolePageRenders(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.api(http.MethodPost, "/api/v1/report", "45.83.64.7,91.240.118.3"); code != http.StatusOK {
		t.Fatal("seed report failed")
	}
	if _, _, err := h.db.AddWhitelist(t.Context(), "198.18.0.0/15", "benchmark range", "tester", 0); err != nil {
		t.Logf("whitelist seed: %v", err)
	}
	a, err := h.db.AddressByIP(t.Context(), "45.83.64.7")
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{
		"/",
		"/?hours=168",
		"/addresses",
		"/addresses?q=45.83&sort=peers&state=all",
		"/addresses?q=45.83.64.0/24",
		"/addresses/" + strconv.FormatInt(a.ID, 10),
		"/whitelist",
		"/whitelist/preview?cidr=45.83.64.0/24",
		"/devices",
		"/devices/" + strconv.FormatInt(h.device.ID, 10),
		"/devices/" + strconv.FormatInt(h.device.ID, 10) + "/scripts",
		"/activity",
		"/audit",
		"/users",
		"/settings",
		"/account",
		"/help",
	}
	for _, p := range paths {
		code, body := h.get(p)
		if code != http.StatusOK {
			t.Errorf("GET %s: %d\n%s", p, code, trunc(body, 400))
			continue
		}
		if strings.Contains(body, "template error") || strings.Contains(body, "<no value>") {
			t.Errorf("GET %s: rendered with template errors\n%s", p, trunc(body, 400))
		}
		if !strings.Contains(body, "</html>") {
			t.Errorf("GET %s: truncated page", p)
		}
	}
}

func TestConsoleMutationsRequireCSRF(t *testing.T) {
	h := newHarness(t)
	form := url.Values{"cidr": {"45.83.64.0/24"}, "csrf": {"wrong"}}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "apb_session", Value: h.cookie})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong CSRF token: expected 403, got %d", resp.StatusCode)
	}
	if n, _ := h.db.WhitelistCount(t.Context()); n != 0 {
		t.Error("a request with a bad CSRF token still changed state")
	}
}

func TestScriptBundleDownloadIssuesAToken(t *testing.T) {
	h := newHarness(t)
	before, _ := h.db.ListTokens(t.Context(), h.device.ID)

	code, body := h.post("/devices/"+strconv.FormatInt(h.device.ID, 10)+"/scripts",
		url.Values{"part": {"install"}})
	if code != http.StatusOK {
		t.Fatalf("download: %d %s", code, trunc(body, 300))
	}
	if !strings.Contains(body, "/system script add") || !strings.Contains(body, "apb-bootstrap") {
		t.Error("the bundle does not look like a RouterOS script")
	}
	if !strings.Contains(body, "timeout=") {
		t.Error("the bundle adds address-list entries without a timeout, which would write them to flash")
	}
	// A backslash-continued line breaks on any router that receives the file with
	// CRLF endings, which is how the first field attempt failed.
	for i, line := range strings.Split(body, "\n") {
		if strings.HasSuffix(strings.TrimRight(line, "\r"), `\`) {
			t.Fatalf("served bundle line %d ends with a continuation backslash: %.80s", i+1, line)
		}
	}
	after, _ := h.db.ListTokens(t.Context(), h.device.ID)
	if len(after) != len(before)+1 {
		t.Errorf("expected one new token, had %d now %d", len(before), len(after))
	}
	if !strings.Contains(body, after[0].Prefix) {
		t.Error("the freshly issued token is not present in the downloaded bundle")
	}
}

func TestReadOnlyAccountCannotMutate(t *testing.T) {
	h := newHarness(t)
	ctx := t.Context()
	if err := h.db.UpdateAdminProfile(ctx, h.admin.ID, "", "", model.RoleViewer, false); err != nil {
		t.Fatal(err)
	}
	code, _ := h.post("/whitelist", url.Values{"cidr": {"45.83.64.0/24"}})
	if code != http.StatusForbidden {
		t.Errorf("viewer POST: expected 403, got %d", code)
	}
	if n, _ := h.db.WhitelistCount(ctx); n != 0 {
		t.Error("a read-only account changed state")
	}
}

func TestBogonsAreRejected(t *testing.T) {
	h := newHarness(t)
	code, body := h.api(http.MethodPost, "/api/v1/report",
		"10.0.0.1,192.168.1.1,127.0.0.1,169.254.1.1,224.0.0.1,::1,fe80::1,not-an-address")
	if code != http.StatusOK {
		t.Fatalf("report: %d", code)
	}
	if fields := strings.Split(body, ","); fields[1] != "0" {
		t.Errorf("private and reserved addresses were accepted: %q", body)
	}
	if n, _ := h.db.BlockedCount(t.Context(), true); n != 0 {
		t.Errorf("%d bogons reached the blocklist", n)
	}
}

func cursorOf(t *testing.T, body string) int64 {
	t.Helper()
	for _, tok := range strings.Split(body, ",") {
		if strings.HasPrefix(tok, "c") {
			n, err := strconv.ParseInt(tok[1:], 10, 64)
			if err == nil {
				return n
			}
		}
	}
	t.Fatalf("no cursor in %q", body)
	return 0
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// The User-Agent gate filters internet noise before the token is checked. It is
// also the setting most able to take an estate offline, because its value is
// baked into a bundle when that bundle is generated, so the rules around it
// need to be exact.
func TestUserAgentGate(t *testing.T) {
	h := newHarness(t)
	if err := h.db.SaveSettings(t.Context(), map[string]string{"require_user_agent": "apb-router"}); err != nil {
		t.Fatal(err)
	}

	call := func(agents ...string) int {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/sync?c=0", nil)
		req.Header.Set("Authorization", "Bearer "+h.token)
		req.Header.Del("User-Agent")
		for _, a := range agents {
			req.Header.Add("User-Agent", a)
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := call("apb-router"); got != http.StatusOK {
		t.Errorf("matching agent: got %d, want 200", got)
	}
	if got := call("something-else"); got != http.StatusUnauthorized {
		t.Errorf("wrong agent: got %d, want 401", got)
	}
	if got := call(); got != http.StatusUnauthorized {
		t.Errorf("no agent: got %d, want 401", got)
	}
	// Clearing the setting must restore every device immediately, with no
	// regeneration: that is the recovery path when the gate is misconfigured.
	if err := h.db.SaveSettings(t.Context(), map[string]string{"require_user_agent": ""}); err != nil {
		t.Fatal(err)
	}
	if got := call("something-else"); got != http.StatusOK {
		t.Errorf("gate disabled: got %d, want 200", got)
	}
}

// A generated bundle must send whatever the gate currently requires, or
// installing it produces a router that authenticates and is still refused.
func TestGeneratedBundleCarriesTheRequiredAgent(t *testing.T) {
	h := newHarness(t)
	if err := h.db.SaveSettings(t.Context(), map[string]string{"require_user_agent": "custom-agent-1"}); err != nil {
		t.Fatal(err)
	}
	code, body := h.post("/devices/"+strconv.FormatInt(h.device.ID, 10)+"/scripts",
		url.Values{"part": {"install"}})
	if code != http.StatusOK {
		t.Fatalf("download: %d %s", code, trunc(body, 200))
	}
	if !strings.Contains(body, `custom-agent-1`) {
		t.Error("the bundle does not send the User-Agent this instance requires")
	}
}
