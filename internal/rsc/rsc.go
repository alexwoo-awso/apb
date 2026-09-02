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

	// AllowInsecureURL permits a plain HTTP endpoint. It exists only so the
	// service can be exercised locally; a token sent over HTTP is readable by
	// anyone on the path, so production always leaves this false.
	AllowInsecureURL bool

	Prefix    string
	Policy    string
	MaxLoops  int
	MaxPages  int
	MaxBatch  int
	Generated string
}

var (
	reIdent   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$`)
	reToken   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	reTime    = regexp.MustCompile(`^(\d+[wdhms])+$`)
	reURL     = regexp.MustCompile(`^https?://[A-Za-z0-9._-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	reUA      = regexp.MustCompile(`^[A-Za-z0-9._/ -]{1,64}$`)
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
		return fmt.Errorf("block timeout %q must look like 520w, 30d or 12h", p.BlockTimeout)
	}
	if !reTime.MatchString(p.SentTimeout) {
		return fmt.Errorf("reported-entry timeout %q must look like 1d", p.SentTimeout)
	}
	if !reUA.MatchString(p.UserAgent) {
		return fmt.Errorf("user agent %q contains characters that cannot be put in a header", p.UserAgent)
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
	return nil
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

	scripts := []struct {
		name string
		body string
		desc string
	}{
		{p.Prefix + "sync", sync, "applies incremental blocklist changes"},
		{p.Prefix + "bootstrap", bootstrap, "rebuilds the whole list after a reboot"},
		{p.Prefix + "report", report, "uploads locally detected addresses"},
		{p.Prefix + "purge", purge, "clears every address APB manages here"},
	}

	var scriptSection strings.Builder
	scriptSection.WriteString(header(p, "scripts", true))
	scriptSection.WriteString(":do { /system script remove [find name~\"^" + p.Prefix + "\"] } on-error={}\n")
	for _, s := range scripts {
		fmt.Fprintf(&scriptSection,
			"/system script add name=\"%s\" policy=%s dont-require-permissions=no comment=\"APB: %s\" source=\"%s\"\n",
			s.name, p.Policy, s.desc, wrapEscaped(escapeSource(s.body), 96))
	}

	var schedSection strings.Builder
	schedSection.WriteString(header(p, "scheduler", false))
	schedSection.WriteString(":do { /system scheduler remove [find name~\"^" + p.Prefix + "\"] } on-error={}\n")
	fmt.Fprintf(&schedSection,
		"/system scheduler add name=\"%ssync\" interval=%ds start-time=startup policy=%s comment=\"APB: poll for changes\" on-event=\"/system script run %ssync\"\n",
		p.Prefix, p.SyncInterval, p.Policy, p.Prefix)
	fmt.Fprintf(&schedSection,
		"/system scheduler add name=\"%sreport\" interval=%ds start-time=startup policy=%s comment=\"APB: upload detections\" on-event=\"/system script run %sreport\"\n",
		p.Prefix, p.ReportInterval, p.Policy, p.Prefix)
	fmt.Fprintf(&schedSection,
		"/system scheduler add name=\"%sboot\" interval=0 start-time=startup policy=%s comment=\"APB: rebuild the RAM-held list after a reboot\" on-event=\"/system script run %sbootstrap\"\n",
		p.Prefix, p.Policy, p.Prefix)

	install := scriptSection.String() + "\n" + strings.TrimPrefix(schedSection.String(), header(p, "scheduler", false)) +
		"\n# Build the list immediately instead of waiting for the first schedule.\n" +
		"/system script run " + p.Prefix + "bootstrap\n"

	var uninstall strings.Builder
	uninstall.WriteString(header(p, "uninstall", false))
	fmt.Fprintf(&uninstall, ":do { /system script run %spurge } on-error={}\n", p.Prefix)
	fmt.Fprintf(&uninstall, ":do { /system scheduler remove [find name~\"^%s\"] } on-error={}\n", p.Prefix)
	fmt.Fprintf(&uninstall, ":do { /system script remove [find name~\"^%s\"] } on-error={}\n", p.Prefix)
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

// wrapEscaped breaks a long escaped string across physical lines using the
// RouterOS continuation convention: a trailing backslash, then indentation
// that the parser discards. Breaks never land inside a two-character escape.
func wrapEscaped(s string, width int) string {
	if width < 16 {
		width = 96
	}
	var b strings.Builder
	col := 0
	for i := 0; i < len(s); {
		n := 1
		if s[i] == '\\' && i+1 < len(s) {
			n = 2
		}
		if col+n > width {
			b.WriteString("\\\n    ")
			col = 4
		}
		b.WriteString(s[i : i+n])
		col += n
		i += n
	}
	return b.String()
}
