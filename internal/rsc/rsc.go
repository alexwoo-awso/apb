// Package rsc generates the RouterOS scripts a device runs.
//
// The generated scripts never touch the router's flash. Blocklist entries are
// added with a timeout, which RouterOS keeps in RAM and drops on reboot, and
// the replication cursor lives in a global variable, which is also RAM only.
// A reboot therefore leaves the router with an empty list and no cursor, which
// is exactly the condition the bootstrap script detects and repairs.
package rsc

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var tmpl = template.Must(template.ParseFS(templateFS, "templates/*.tmpl"))

// Params is everything the generator needs. Every field that reaches the
// generated script is validated, because the output is code that runs on a
// router with write privileges.
type Params struct {
	InstanceName string
	DeviceName   string
	BaseURL      string
	Token        string

	Branch         string // v6 | v7
	ListName       string
	DetectList     string
	SentList       string
	BlockTimeout   string
	SentTimeout    string
	SyncInterval   int
	ReportInterval int
	UserAgent      string
	VerifyCert     string
	IPv6           bool

	// Mode is the /tool fetch transport, derived from BaseURL. RouterOS 6
	// defaults it to http and rejects check-certificate outside https mode, so
	// an https endpoint without an explicit mode fails every fetch.
	Mode string

	// AllowInsecureURL permits a plain HTTP endpoint. It exists only so the
	// service can be exercised locally; a token sent over HTTP is readable by
	// anyone on the path, so production always leaves this false.
	AllowInsecureURL bool

	// StateAddress is the placeholder address of the cursor marker entry. It is
	// never matched by any firewall rule; only the list membership and the
	// comment matter.
	StateAddress string

	Prefix    string
	Policy    string
	MaxLoops  int
	MaxPages  int
	MaxBatch  int
	Generated string
}

// timeoutCeiling is the largest address-list timeout the generator will emit.
//
// RouterOS refuses a long timeout on an address-list entry, and it refuses the
// entry rather than clamping the value, so a router given too large a number
// runs the scripts, reports a clean rebuild and holds nothing at all. This is
// not a version difference: both branches refuse it.
//
// Measured on real hardware:
//
//	RouterOS 6.49.20   1d ok  4w ok                       52w refused  520w refused
//	RouterOS 7.x       1d ok  4w ok  6w ok  7w ok  8w ok  52w refused  520w refused
//
// 8w is therefore the largest value observed to work anywhere, and it is the
// cap. The true boundary lies somewhere between 8w and 52w; apb-test walks a
// ladder so an operator can find their own build's limit rather than trusting a
// number in documentation, which is how the ten-year figure got in here.
const timeoutCeiling = 8 * 7 * 24 * time.Hour

// Per-branch defaults, each the longest value proven to work on that branch.
//
// RouterOS 6 is only proven to 4w because the finer probes did not exist when
// the 6.49 router was measured; it may well accept more, and apb-test will say
// so. RouterOS 7 is proven to 8w. Neither accepts 52w.
//
// The length matters less than it looks: the server notices when a list has
// drifted and calls for a rebuild, so the timeout only governs how long a
// router cut off from the server keeps protecting itself.
const (
	DefaultBlockTimeoutV6 = "4w"
	DefaultBlockTimeoutV7 = "8w"
)

// DefaultBlockTimeout returns the longest entry timeout proven to work on a
// branch. An unknown branch gets the more conservative of the two.
func DefaultBlockTimeout(branch string) string {
	if branch == "v7" {
		return DefaultBlockTimeoutV7
	}
	return DefaultBlockTimeoutV6
}

var (
	reIdent   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$`)
	reToken   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	reTime    = regexp.MustCompile(`^(\d+[wdhms])+$`)
	reURL     = regexp.MustCompile(`^https?://[A-Za-z0-9._-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	reUA      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	verifyOpt = map[string]bool{"yes": true, "yes-without-crl": true, "no": true}
)

// FromDevice builds generator parameters from a stored device plus the token
// the operator has just been shown.
func FromDevice(d model.Device, baseURL, instance, token, userAgent string) Params {
	p := Params{
		InstanceName:   instance,
		DeviceName:     d.Name,
		BaseURL:        strings.TrimRight(baseURL, "/"),
		Token:          token,
		Branch:         d.ROSBranch,
		ListName:       d.ListName,
		DetectList:     d.DetectList,
		SentList:       d.DetectList + "_sent",
		BlockTimeout:   d.BlockTimeout,
		SentTimeout:    "1d",
		SyncInterval:   d.SyncInterval,
		ReportInterval: d.ReportInterval,
		UserAgent:      userAgent,
		VerifyCert:     d.VerifyCert,
		IPv6:           d.IPv6,
		StateAddress:   "192.0.2.1",
		Prefix:         "apb-",
		Policy:         "read,write,test",
		MaxLoops:       20,
		MaxPages:       500,
		MaxBatch:       300,
		Generated:      time.Now().UTC().Format("2006-01-02 15:04:05Z"),
	}
	if p.UserAgent == "" {
		p.UserAgent = "apb-router"
	}
	p.Mode = "https"
	if strings.HasPrefix(p.BaseURL, "http://") {
		p.Mode = "http"
	}
	return p
}

func (p *Params) validate() error {
	if p.DeviceName == "" {
		return fmt.Errorf("device name is required")
	}
	if !reURL.MatchString(p.BaseURL) {
		return fmt.Errorf("public base URL %q is not usable in a script; set it to something like https://apb.example.org", p.BaseURL)
	}
	if strings.HasPrefix(p.BaseURL, "http://") && !p.AllowInsecureURL {
		return fmt.Errorf("refusing to generate scripts for the plain HTTP address %s: the device token would cross the network in clear text. Set APB_BASE_URL to an https:// address", p.BaseURL)
	}
	if !reToken.MatchString(p.Token) {
		return fmt.Errorf("token has an unexpected shape")
	}
	for name, v := range map[string]string{
		"address list":   p.ListName,
		"detection list": p.DetectList,
		"reported list":  p.SentList,
	} {
		if !reIdent.MatchString(v) {
			return fmt.Errorf("%s name %q must be letters, digits, dot, dash or underscore", name, v)
		}
	}
	if !reTime.MatchString(p.BlockTimeout) {
		return fmt.Errorf("entry timeout %q must look like 4w, 30d or 12h", p.BlockTimeout)
	}
	d, err := parseROSDuration(p.BlockTimeout)
	if err != nil {
		return fmt.Errorf("entry timeout %q: %w", p.BlockTimeout, err)
	}
	if d > timeoutCeiling {
		return fmt.Errorf("entry timeout %s is longer than RouterOS accepts on an address-list "+
			"entry: the router would refuse every address and hold nothing while still reporting "+
			"a clean rebuild. 4w works on every router tested and 8w is the largest observed to "+
			"work anywhere; run apb-test on the router to find its own ceiling", p.BlockTimeout)
	}
	if !reTime.MatchString(p.SentTimeout) {
		return fmt.Errorf("reported-entry timeout %q must look like 1d", p.SentTimeout)
	}
	if !reUA.MatchString(p.UserAgent) {
		return fmt.Errorf("client identity %q must be letters, digits, dot, dash or underscore: "+
			"it travels in the request URL, and RouterOS cannot percent-encode", p.UserAgent)
	}
	if !verifyOpt[p.VerifyCert] {
		return fmt.Errorf("certificate check %q must be yes, yes-without-crl or no", p.VerifyCert)
	}
	if p.SyncInterval < 5 || p.SyncInterval > 86400 {
		return fmt.Errorf("sync interval must be between 5 and 86400 seconds")
	}
	if p.ReportInterval < 30 || p.ReportInterval > 86400 {
		return fmt.Errorf("report interval must be between 30 and 86400 seconds")
	}
	if p.Branch != "v6" && p.Branch != "v7" {
		return fmt.Errorf("RouterOS branch must be v6 or v7")
	}
	if !reIdent.MatchString(strings.TrimSuffix(p.Prefix, "-")) {
		return fmt.Errorf("script name prefix %q is not usable", p.Prefix)
	}
	if p.Mode != "http" && p.Mode != "https" {
		return fmt.Errorf("fetch mode %q must be http or https", p.Mode)
	}
	return nil
}

// parseROSDuration reads a RouterOS time literal such as "4w2d" or "520w".
func parseROSDuration(s string) (time.Duration, error) {
	units := map[byte]time.Duration{
		'w': 7 * 24 * time.Hour,
		'd': 24 * time.Hour,
		'h': time.Hour,
		'm': time.Minute,
		's': time.Second,
	}
	var total time.Duration
	num := 0
	seen := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			num = num*10 + int(c-'0')
			seen = true
		default:
			u, ok := units[c]
			if !ok || !seen {
				return 0, fmt.Errorf("unrecognised time unit %q", string(c))
			}
			total += time.Duration(num) * u
			num, seen = 0, false
		}
	}
	if seen {
		return 0, fmt.Errorf("a number with no unit")
	}
	if total <= 0 {
		return 0, fmt.Errorf("must be greater than zero")
	}
	return total, nil
}

// TimeoutWithinBranch reports whether a timeout is one this branch is known to
// accept. It is deliberately conservative: a value that has not been observed
// to work is treated as one that does not, because the failure mode is a router
// that reports a clean rebuild and holds nothing.
func TimeoutWithinBranch(branch, timeout string) bool {
	d, err := parseROSDuration(timeout)
	if err != nil {
		return false
	}
	max, err := parseROSDuration(DefaultBlockTimeout(branch))
	if err != nil {
		return false
	}
	return d <= max
}

// Bundle is the set of files the console offers for download.
type Bundle struct {
	Scripts   string // script definitions only
	Scheduler string // scheduler entries only
	Install   string // both, plus an immediate first run
	Uninstall string // removes everything this generator installs
	Firewall  string // example detection rules, never installed automatically
	Params    Params
}

// Generate renders the whole bundle.
func Generate(p Params) (Bundle, error) {
	if err := p.validate(); err != nil {
		return Bundle{}, err
	}
	sync, err := render("sync.rsc.tmpl", p)
	if err != nil {
		return Bundle{}, err
	}
	bootstrap, err := render("bootstrap.rsc.tmpl", p)
	if err != nil {
		return Bundle{}, err
	}
	report, err := render("report.rsc.tmpl", p)
	if err != nil {
		return Bundle{}, err
	}
	purge, err := render("purge.rsc.tmpl", p)
	if err != nil {
		return Bundle{}, err
	}
	probe, err := render("test.rsc.tmpl", p)
	if err != nil {
		return Bundle{}, err
	}

	scripts := []struct {
		name string
		body string
		desc string
	}{
		{p.Prefix + "sync", sync, "applies incremental blocklist changes"},
		{p.Prefix + "bootstrap", bootstrap, "rebuilds the whole list after a reboot"},
		{p.Prefix + "report", report, "uploads locally detected addresses"},
		{p.Prefix + "purge", purge, "clears every address APB manages here"},
		{p.Prefix + "test", probe, "one-shot connectivity check, run it by hand"},
	}

	var scriptSection strings.Builder
	scriptSection.WriteString(header(p, "scripts", true))
	scriptSection.WriteString(assemblerPreamble)
	for _, s := range scripts {
		writeScript(&scriptSection, p, s.name, s.desc, s.body)
	}
	scriptSection.WriteString("\n:set apbSrc \"\"\n")

	var schedSection strings.Builder
	schedSection.WriteString(header(p, "scheduler", false))
	for _, s := range []struct {
		name, interval, desc, run string
	}{
		{p.Prefix + "sync", fmt.Sprintf("%ds", p.SyncInterval), "poll for changes", p.Prefix + "sync"},
		{p.Prefix + "report", fmt.Sprintf("%ds", p.ReportInterval), "upload detections", p.Prefix + "report"},
		{p.Prefix + "boot", "0", "rebuild the RAM-held list after a reboot", p.Prefix + "bootstrap"},
	} {
		fmt.Fprintf(&schedSection, "%s\n", removeLine("/system scheduler", s.name))
		fmt.Fprintf(&schedSection,
			"/system scheduler add name=\"%s\" interval=%s start-time=startup policy=%s comment=\"APB: %s\" on-event=\"/system script run %s\"\n",
			s.name, s.interval, p.Policy, s.desc, s.run)
	}

	install := scriptSection.String() + "\n" + strings.TrimPrefix(schedSection.String(), header(p, "scheduler", false)) +
		"\n# Build the list immediately instead of waiting for the first schedule.\n" +
		"/system script run " + p.Prefix + "bootstrap\n"

	var uninstall strings.Builder
	uninstall.WriteString(header(p, "uninstall", false))
	fmt.Fprintf(&uninstall, ":do { /system script run %spurge } on-error={ :log warning \"APB: purge failed\" }\n", p.Prefix)
	for _, n := range []string{p.Prefix + "sync", p.Prefix + "report", p.Prefix + "boot"} {
		fmt.Fprintf(&uninstall, "%s\n", removeLine("/system scheduler", n))
	}
	for _, s := range scripts {
		fmt.Fprintf(&uninstall, "%s\n", removeLine("/system script", s.name))
	}
	uninstall.WriteString(":log info \"APB: removed\"\n")

	firewall, err := render("firewall.rsc.tmpl", p)
	if err != nil {
		return Bundle{}, err
	}

	return Bundle{
		Scripts:   scriptSection.String(),
		Scheduler: schedSection.String(),
		Install:   install,
		Uninstall: uninstall.String(),
		Firewall:  firewall,
		Params:    p,
	}, nil
}

func render(name string, p Params) (string, error) {
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, name, p); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return b.String(), nil
}

func header(p Params, kind string, secret bool) string {
	h := fmt.Sprintf(`# APB %s for "%s" (RouterOS %s)
# Generated %s by %s.
`, kind, p.DeviceName, p.Branch, p.Generated, p.InstanceName)
	if secret {
		h += `#
# This file contains the API token for this router. Treat it as a password:
# do not commit it, do not share it, and remove the file from the router once
# the import has finished. If it leaks, revoke the token in the console and
# issue a new one.
`
	}
	return h + `#
# Import with:  /import file-name=<this file>
`
}

// maxChunk caps how much escaped script text goes on one physical line of the
// generated file. It is a readability and safety margin, not a hard RouterOS
// limit; anything comfortably under a few hundred characters is safe to import.
const maxChunk = 170

const assemblerPreamble = `#
# The script bodies below are assembled one piece at a time into a variable and
# then installed. That is deliberately more verbose than the single quoted
# string RouterOS itself exports, and it is what makes this file safe to move
# between machines: there are no line continuations, so a file converted to
# CRLF on the way here still imports correctly.
#
:global apbSrc
`

// removeLine emits an idempotent removal for one named item. RouterOS errors
// on a removal that matches nothing in some versions, and an error inside
// /import aborts the whole file, so each one is guarded.
func removeLine(path, name string) string {
	return fmt.Sprintf(`:do { %s remove [find name="%s"] } on-error={ :log debug "APB: no previous %s" }`,
		path, name, name)
}

// writeScript emits the assembly of one script body and the command that
// installs it.
func writeScript(b *strings.Builder, p Params, name, desc, body string) {
	fmt.Fprintf(b, "\n# --- %s: %s\n", name, desc)
	b.WriteString(":set apbSrc \"\"\n")
	for _, chunk := range chunkEscaped(escapeSource(body), maxChunk) {
		fmt.Fprintf(b, ":set apbSrc ($apbSrc . \"%s\")\n", chunk)
	}
	fmt.Fprintf(b, "%s\n", removeLine("/system script", name))
	fmt.Fprintf(b,
		"/system script add name=\"%s\" policy=%s dont-require-permissions=no comment=\"APB: %s\" source=$apbSrc\n",
		name, p.Policy, desc)
}

// chunkEscaped splits already-escaped script text into pieces that each fit on
// one line, never splitting a two-character escape and preferring to end a
// piece at a line break in the script so the generated file stays readable.
func chunkEscaped(s string, max int) []string {
	if max < 32 {
		max = maxChunk
	}
	var out []string
	for i := 0; i < len(s); {
		j, col, lastBreak := i, 0, -1
		for j < len(s) {
			n := 1
			if s[j] == '\\' && j+1 < len(s) {
				n = 2
			}
			if col+n > max {
				break
			}
			j += n
			col += n
			// A "\r\n" pair ends a line of the script: a natural break point.
			if j >= 4 && s[j-4:j] == `\r\n` {
				lastBreak = j
			}
		}
		if j >= len(s) {
			out = append(out, s[i:])
			break
		}
		if lastBreak > i {
			j = lastBreak
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

// escapeSource renders a script body as a RouterOS quoted string, using the
// same escapes the router's own export produces.
func escapeSource(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString(`\$`)
		case '?':
			b.WriteString(`\?`)
		case '\n':
			b.WriteString(`\r\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
