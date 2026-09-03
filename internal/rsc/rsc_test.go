package rsc

import (
	"strings"
	"testing"

	"github.com/alexwoo-awso/apb/internal/model"
)

func testDevice() model.Device {
	return model.Device{
		Name:           "edge-1",
		ROSBranch:      "v7",
		ListName:       "APB",
		DetectList:     "APB_detect",
		BlockTimeout:   "520w",
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
