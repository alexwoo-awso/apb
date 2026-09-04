package rsc

import (
	"strings"
	"testing"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

func testDevice() model.Device {
	return model.Device{
		Name:           "edge-1",
		ROSBranch:      "v7",
		ListName:       "APB",
		DetectList:     "APB_detect",
		BlockTimeout:   "4w",
		VerifyCert:     "yes-without-crl",
		SyncInterval:   15,
		ReportInterval: 300,
	}
}

func TestGenerateProducesEveryFile(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for name, body := range map[string]string{
		"scripts":   b.Scripts,
		"scheduler": b.Scheduler,
		"install":   b.Install,
		"uninstall": b.Uninstall,
		"firewall":  b.Firewall,
	} {
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s is empty", name)
		}
	}
	for _, want := range []string{"apb-sync", "apb-bootstrap", "apb-report", "apb-purge"} {
		if !strings.Contains(b.Scripts, `name="`+want+`"`) {
			t.Errorf("scripts missing %s", want)
		}
	}
	if !strings.Contains(b.Scheduler, "interval=15s") {
		t.Error("scheduler does not use the device sync interval")
	}
	if !strings.Contains(b.Scheduler, "start-time=startup") {
		t.Error("scheduler does not arm the reboot rebuild")
	}
}

// The whole point of the rework: nothing the router adds may be written to
// flash, which in RouterOS means every address-list entry carries a timeout.
func TestEveryAddressListAddCarriesATimeout(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	body := b.Install
	for i := 0; ; {
		j := strings.Index(body[i:], "address-list add")
		if j < 0 {
			break
		}
		start := i + j
		end := start + strings.Index(body[start:], "on-error")
		if end < start {
			end = len(body)
		}
		if !strings.Contains(body[start:end], "timeout=") {
			t.Fatalf("address-list add without a timeout near: %.120s", body[start:])
		}
		i = start + len("address-list add")
	}
}

func TestGeneratedSourceIsBalanced(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Unescape the wrapped source back to the script body and check that the
	// RouterOS block structure is balanced, which is the failure mode a typo
	// in a template would produce.
	for _, line := range strings.Split(b.Scripts, "\n") {
		_ = line
	}
	body := unwrap(b.Scripts)
	if depth := braceDepth(body); depth != 0 {
		t.Errorf("unbalanced braces in generated scripts: depth %d", depth)
	}
}

func unwrap(s string) string {
	s = strings.ReplaceAll(s, "\\\n    ", "")
	s = strings.ReplaceAll(s, `\r\n`, "\n")
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\$`, `$`)
	s = strings.ReplaceAll(s, `\?`, `?`)
	return s
}

func braceDepth(s string) int {
	depth, inString := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			inString = !inString
		case '{':
			if !inString {
				depth++
			}
		case '}':
			if !inString {
				depth--
			}
		}
	}
	return depth
}

func TestValidationRejectsUnsafeInput(t *testing.T) {
	base := testDevice()
	cases := map[string]func(*model.Device){
		"list name with a quote":  func(d *model.Device) { d.ListName = `A"; /system reboot; "` },
		"list name with a space":  func(d *model.Device) { d.ListName = "my list" },
		"nonsense block timeout":  func(d *model.Device) { d.BlockTimeout = "forever" },
		"unknown verify mode":     func(d *model.Device) { d.VerifyCert = "maybe" },
		"sync interval too small": func(d *model.Device) { d.SyncInterval = 1 },
	}
	for name, mutate := range cases {
		d := base
		mutate(&d)
		if _, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	if _, err := Generate(FromDevice(base, "http://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")); err == nil {
		t.Error("plain http base URL: expected rejection")
	}
	if _, err := Generate(FromDevice(base, "https://apb.example.org", "APB", "bad token!", "apb-router")); err == nil {
		t.Error("malformed token: expected rejection")
	}
}

func TestV4OnlyDeviceGetsNoIPv6Commands(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(unwrap(b.Scripts), "/ipv6 firewall") {
		t.Error("v4-only device received IPv6 commands")
	}

	d := testDevice()
	d.IPv6 = true
	b6, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router"))
	if err != nil {
		t.Fatalf("generate v6: %v", err)
	}
	if !strings.Contains(unwrap(b6.Scripts), "/ipv6 firewall address-list add") {
		t.Error("IPv6 device did not receive IPv6 commands")
	}
}

// The generated file must contain no line continuations. MikroTik's own export
// format wraps long strings with a trailing backslash, which breaks in two ways
// this generator cannot control: the router strips leading whitespace on the
// continuation line, silently eating a space that belongs to the script, and a
// file converted to CRLF anywhere in transit puts a carriage return after the
// backslash so the line stops continuing at all. Both produce an import that
// fails or, worse, one that succeeds with a corrupted script.
func TestGeneratedFilesHaveNoLineContinuations(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for name, body := range map[string]string{
		"scripts": b.Scripts, "scheduler": b.Scheduler,
		"install": b.Install, "uninstall": b.Uninstall, "firewall": b.Firewall,
	} {
		for i, line := range strings.Split(body, "\n") {
			if strings.HasSuffix(line, `\`) {
				t.Errorf("%s line %d ends with a continuation backslash: %.80s", name, i+1, line)
			}
			if len(line) > 400 {
				t.Errorf("%s line %d is %d characters long", name, i+1, len(line))
			}
		}
	}
}

// Every line must survive a round trip through CRLF, which is what happens when
// the file is downloaded on Windows or opened in an editor before being sent to
// the router.
func TestInstallSurvivesCRLFConversion(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	crlf := strings.ReplaceAll(b.Install, "\n", "\r\n")
	got := assembleSource(t, crlf, "apb-sync")
	want := assembleSource(t, b.Install, "apb-sync")
	if got != want {
		t.Error("the assembled script differs after CRLF conversion")
	}
	if !strings.Contains(want, `:local Hdr ("Authorization: Bearer "`) {
		t.Errorf("assembled script lost its spacing:\n%.400s", want)
	}
}

// TestAssembledSourceMatchesTheTemplate proves the pieces the .rsc appends
// reconstruct the script body exactly, so a bug in chunking or escaping cannot
// ship a subtly different script than the one under test.
func TestAssembledSourceMatchesTheTemplate(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, tc := range []struct{ script, template string }{
		{"apb-sync", "sync.rsc.tmpl"},
		{"apb-bootstrap", "bootstrap.rsc.tmpl"},
		{"apb-report", "report.rsc.tmpl"},
		{"apb-purge", "purge.rsc.tmpl"},
	} {
		want, err := render(tc.template, p)
		if err != nil {
			t.Fatal(err)
		}
		got := assembleSource(t, b.Install, tc.script)
		if got != strings.ReplaceAll(want, "\r\n", "\n") {
			t.Errorf("%s: assembled source does not match the template", tc.script)
		}
	}
}

// assembleSource replays the ":set apbSrc ($apbSrc . \"...\")" lines belonging
// to one script, exactly as RouterOS would, and unescapes the result.
func assembleSource(t *testing.T, rsc, script string) string {
	t.Helper()
	var b strings.Builder
	inSection := false
	for _, line := range strings.Split(strings.ReplaceAll(rsc, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "# --- "+script+":"):
			inSection = true
		case strings.HasPrefix(line, "# --- "):
			inSection = false
		case inSection && strings.HasPrefix(line, `:set apbSrc ($apbSrc . "`):
			chunk := strings.TrimSuffix(strings.TrimPrefix(line, `:set apbSrc ($apbSrc . "`), `")`)
			b.WriteString(chunk)
		}
	}
	return unescapeRSC(b.String())
}

func unescapeRSC(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'r':
			// The script uses CRLF; the template side uses LF.
		case 'n':
			b.WriteByte('\n')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// RouterOS 6 defaults /tool fetch to mode=http and rejects check-certificate
// outside https mode, so an https endpoint without an explicit mode fails every
// single fetch — which is exactly how the first field install failed.
func TestEveryFetchCarriesTheTransportMode(t *testing.T) {
	for _, tc := range []struct {
		base, wantMode string
		wantCertOpt    bool
	}{
		{"https://apb.example.org", "https", true},
		{"http://localhost:8080", "http", false},
	} {
		d := testDevice()
		p := FromDevice(d, tc.base, "APB", "apb_abcdefghijklmnop", "apb-router")
		p.AllowInsecureURL = true
		b, err := Generate(p)
		if err != nil {
			t.Fatalf("%s: %v", tc.base, err)
		}
		body := unwrap(b.Install)
		fetches := strings.Count(body, "/tool fetch")
		if fetches == 0 {
			t.Fatalf("%s: no fetch calls in the bundle", tc.base)
		}
		if got := strings.Count(body, "mode="+tc.wantMode); got != fetches {
			t.Errorf("%s: %d fetch calls but %d carry mode=%s", tc.base, fetches, got, tc.wantMode)
		}
		// check-certificate is only accepted in https mode.
		if got := strings.Contains(body, "check-certificate="); got != tc.wantCertOpt {
			t.Errorf("%s: check-certificate present=%v, want %v", tc.base, got, tc.wantCertOpt)
		}
	}
}

func TestBundleShipsAConnectivityTest(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(b.Install, `name="apb-test"`) {
		t.Error("the bundle does not install the connectivity test")
	}
	body := unwrap(b.Install)
	if !strings.Contains(body, "/whoami") {
		t.Error("the connectivity test does not call whoami")
	}
	// It must not be scheduled: it exists to be run by hand.
	if strings.Contains(b.Scheduler, "apb-test") {
		t.Error("the connectivity test should not be scheduled")
	}
}

// The client identity travels in the query string. Headers were the wrong
// place: RouterOS sets User-Agent itself, and adding a custom header made
// /tool fetch fail outright on RouterOS 6, so a request that used to arrive
// stopped arriving at all. A URL the script composes cannot be interfered with.
func TestIdentityTravelsInTheQueryString(t *testing.T) {
	d := testDevice()
	p := FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "mrhyde")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	body := unwrap(b.Install)

	for _, want := range []string{
		`"/sync?k=" . $UA`,
		`"/full?k=" . $UA`,
		`"/report?k=" . $UA`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("no identity in the URL for %s", want)
		}
	}
	// Page two of a rebuild must extend the query, not start a new one.
	if !strings.Contains(body, `$U . "&a=" . $Next`) {
		t.Error("the rebuild page marker would start a second query string")
	}
	// Only the two headers that provably reach the server. The connectivity
	// probe is exempt: sending a custom header is the whole point of it, and it
	// only ever runs by hand.
	for _, name := range []string{"sync.rsc.tmpl", "bootstrap.rsc.tmpl", "report.rsc.tmpl"} {
		script, err := render(name, p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(script, "X-Apb-Agent") {
			t.Errorf("%s carries a custom header; RouterOS 6 refuses the fetch", name)
		}
	}
	if n := strings.Count(body, `:local Hdr ("Authorization: Bearer " . $Token . ",User-Agent: " . $UA)`); n < 4 {
		t.Errorf("expected the two-header form in every script, found %d", n)
	}
}

// RouterOS 6 cannot percent-encode, so an identity that is not URL-safe would
// silently corrupt every request rather than failing loudly at generation.
func TestIdentityMustBeURLSafe(t *testing.T) {
	for _, bad := range []string{"My Agent", "agent/1.0", "a?b", "a&b", "a=b", ""} {
		_, err := Generate(FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", bad))
		if err == nil && bad != "" {
			t.Errorf("identity %q was accepted", bad)
		}
	}
	// Empty falls back to the default, which is safe.
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "")
	if p.UserAgent != "apb-router" {
		t.Errorf("empty identity should default, got %q", p.UserAgent)
	}
	if _, err := Generate(p); err != nil {
		t.Errorf("default identity rejected: %v", err)
	}
}

// RouterOS 6 refused the fetch when a custom header was present, so the report
// metadata headers are v7 only.
func TestReportMetadataHeadersAreV7Only(t *testing.T) {
	for _, tc := range []struct {
		branch string
		want   bool
	}{{"v7", true}, {"v6", false}} {
		d := testDevice()
		d.ROSBranch = tc.branch
		if tc.branch == "v6" {
			d.VerifyCert = "no"
		}
		b, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router"))
		if err != nil {
			t.Fatalf("%s: %v", tc.branch, err)
		}
		if got := strings.Contains(unwrap(b.Install), "X-Apb-Identity"); got != tc.want {
			t.Errorf("%s: metadata headers present=%v, want %v", tc.branch, got, tc.want)
		}
	}
}

// The cursor must survive between scheduler runs. It was held only in a
// RouterOS :global, and on a real 6.49 router that global did not survive from
// one invocation to the next: every poll saw no cursor, ran a full rebuild, and
// never reached the incremental sync at all. The cursor is now also written to
// an address-list marker, which is ordinary router state and persists exactly
// as the blocklist does.
func TestCursorIsPersistedOutsideTheGlobal(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sync, err := render("sync.rsc.tmpl", p)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := render("bootstrap.rsc.tmpl", p)
	if err != nil {
		t.Fatal(err)
	}
	purge, err := render("purge.rsc.tmpl", p)
	if err != nil {
		t.Fatal(err)
	}

	// Sync recovers a cursor it does not hold before deciding to rebuild.
	load := strings.Index(sync, "address-list find list=$State")
	decide := strings.Index(sync, `:log info "APB: no cursor held`)
	if load < 0 || decide < 0 {
		t.Fatal("sync does not both recover and check the cursor")
	}
	if load > decide {
		t.Error("sync decides to rebuild before trying to recover the cursor")
	}

	// Both writers store it, and the marker must carry a timeout or it would be
	// written to the router's flash, which is the thing this project exists to
	// avoid.
	for name, body := range map[string]string{"sync": sync, "bootstrap": boot} {
		i := strings.Index(body, "address-list add list=$State")
		if i < 0 {
			t.Errorf("%s never records the cursor", name)
			continue
		}
		if !strings.Contains(body[i:i+160], "timeout="+p.BlockTimeout) {
			t.Errorf("%s writes the cursor marker without a timeout, which puts it on flash", name)
		}
	}

	if !strings.Contains(purge, "list=$State") {
		t.Error("purge leaves the cursor marker behind")
	}
	// The rebuild must report what it actually stored, not what it received:
	// logging the received value is why a cursor that never persisted looked
	// like a success for four releases.
	if !strings.Contains(boot, `cursor now " . $apbCursor`) {
		t.Error("the rebuild does not report the cursor it stored")
	}
	// It must also report how many of the addresses it was sent it actually
	// kept. A router that refuses the timeout stores none of them and otherwise
	// looks identical to a clean rebuild.
	if !strings.Contains(boot, `$Total . " of " . $Recv`) {
		t.Error("the rebuild does not report stored against received")
	}
	if strings.Contains(b.Install, "cursor "+`" . $NewCursor`) {
		t.Error("the rebuild still reports the received cursor rather than the stored one")
	}
}

// The timeout is written as a literal rather than passed through a RouterOS
// variable. A 6.49 router refused every "address-list add ... timeout=" the
// scripts issued, and passing the value through a :local was one of two
// candidate causes; a literal is what a person would type at the CLI and
// removes the conversion step entirely.
func TestTimeoutIsWrittenAsALiteral(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	for _, name := range []string{"sync.rsc.tmpl", "bootstrap.rsc.tmpl", "report.rsc.tmpl"} {
		body, err := render(name, p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, "timeout=$") {
			t.Errorf("%s passes a timeout through a variable", name)
		}
		for i := 0; ; {
			j := strings.Index(body[i:], "address-list add")
			if j < 0 {
				break
			}
			start := i + j
			window := body[start:min(start+200, len(body))]
			if !strings.Contains(window, "timeout=") {
				t.Errorf("%s: an add with no timeout would land on flash: %.100s", name, window)
			}
			i = start + len("address-list add")
		}
	}
}

// RouterOS refuses a long address-list timeout, and refuses the entry rather
// than clamping the value, so a router given too large a number runs the
// scripts, reports a clean rebuild and holds nothing. Both branches do it: a
// 7.x router refuses 52w exactly as a 6.49 one does, which is why this is not
// conditioned on the branch.
func TestTimeoutBeyondWhatRouterOSAcceptsIsRefused(t *testing.T) {
	for _, tc := range []struct {
		timeout string
		ok      bool
	}{
		{"1d", true}, {"4w", true}, {"30d", true}, {"7w", true}, {"8w", true},
		{"9w", false}, {"52w", false}, {"520w", false},
	} {
		for _, branch := range []string{"v6", "v7"} {
			d := testDevice()
			d.ROSBranch = branch
			d.BlockTimeout = tc.timeout
			if branch == "v6" {
				d.VerifyCert = "no"
			}
			_, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router"))
			if (err == nil) != tc.ok {
				t.Errorf("%s timeout %s: accepted=%v, want %v (%v)", branch, tc.timeout, err == nil, tc.ok, err)
			}
		}
	}
}

func TestParseROSDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"1d":     24 * time.Hour,
		"4w":     28 * 24 * time.Hour,
		"520w":   520 * 7 * 24 * time.Hour,
		"4w2d":   30 * 24 * time.Hour,
		"12h":    12 * time.Hour,
		"1w1d1h": (7*24 + 24 + 1) * time.Hour,
	}
	for in, want := range cases {
		got, err := parseROSDuration(in)
		if err != nil || got != want {
			t.Errorf("%s: got %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "4", "w", "4x", "abc", "0s"} {
		if _, err := parseROSDuration(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A router that refuses the entry timeout receives addresses and stores none,
// while every other signal — the fetch, the cursor, the rebuild message — looks
// exactly like success. That combination hid the defect for nine releases, so
// both scripts now check for it explicitly.
func TestScriptsReportWhenNothingWasStored(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	for _, name := range []string{"sync.rsc.tmpl", "bootstrap.rsc.tmpl"} {
		body, err := render(name, p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "stored none of them") {
			t.Errorf("%s does not notice receiving addresses and storing none", name)
		}
		if !strings.Contains(body, "timeout="+p.BlockTimeout) {
			t.Errorf("%s does not name the timeout being refused", name)
		}
	}
}

// The default entry timeout is the longest value proven to work on that branch,
// not a single conservative figure for both.
func TestDefaultTimeoutIsThePerBranchMaximum(t *testing.T) {
	if DefaultBlockTimeout("v6") != "4w" {
		t.Errorf("v6 default is %q", DefaultBlockTimeout("v6"))
	}
	if DefaultBlockTimeout("v7") != "8w" {
		t.Errorf("v7 default is %q", DefaultBlockTimeout("v7"))
	}
	// An unknown branch takes the safer of the two.
	if DefaultBlockTimeout("") != "4w" {
		t.Errorf("unknown branch default is %q", DefaultBlockTimeout(""))
	}
	for _, tc := range []struct {
		branch, timeout string
		within          bool
	}{
		{"v6", "4w", true}, {"v6", "1d", true}, {"v6", "8w", false}, {"v6", "520w", false},
		{"v7", "8w", true}, {"v7", "4w", true}, {"v7", "12w", false},
		{"v7", "nonsense", false},
	} {
		if got := TimeoutWithinBranch(tc.branch, tc.timeout); got != tc.within {
			t.Errorf("%s %s: within=%v, want %v", tc.branch, tc.timeout, got, tc.within)
		}
	}
}

// A router polls four times a minute for ever, so anything logged on a poll
// where nothing changed is noise. The cursor recovery notice was exactly that:
// it fires on every run, because the RouterOS global does not persist and the
// marker is therefore always the source.
//
// Every message sync may log at info is listed here, and each is a real state
// change that happens rarely. Adding one means deciding, deliberately, that an
// operator wants to see it four times a minute.
func TestASteadyStatePollLogsNothing(t *testing.T) {
	allowed := []string{
		"APB: no cursor held on this router, rebuilding the list", // after a reboot
		"APB: cursor too old, falling back to a full rebuild",     // history pruned
		"APB: applied +", // addresses changed
	}
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	body, err := render("sync.rsc.tmpl", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range strings.Split(body, ":log info")[1:] {
		ok := false
		for _, a := range allowed {
			if strings.Contains(chunk[:min(len(chunk), 120)], a) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("sync logs an unlisted message at info: %.90s", strings.TrimSpace(chunk))
		}
	}
	if strings.Contains(body, `:log info ("APB: recovered cursor`) {
		t.Error("the cursor recovery notice is still at info level")
	}
	if !strings.Contains(body, `:log debug ("APB: recovered cursor`) {
		t.Error("the cursor recovery notice should still be available at debug level")
	}
}
