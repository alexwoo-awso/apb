package adminui

import (
	"html/template"
	"net/http"
)

// Hint is the explainer card shown at the top of a section the first time an
// administrator opens it. Each card is dismissed per account and can be
// brought back from the help page, so the console explains itself once without
// nagging afterwards.
type Hint struct {
	Key   string
	Title string
	Body  template.HTML
	Steps []string
}

var hints = map[string]Hint{
	"dashboard": {
		Key:   "dashboard",
		Title: "What this dashboard shows",
		Body: `<p>APB collects abusive source addresses from your MikroTik routers, merges them
			into one shared blocklist, and pushes that list back out to every router within seconds.</p>
		<p>The numbers below count the <em>shared</em> list, not what any single router happens to hold.
			The map and the tables underneath rank where the traffic comes from, and the
			<strong>routers</strong> column tells you how many separate devices independently saw the
			same address, which is the strongest signal that a block is justified.</p>`,
		Steps: []string{
			"Register a router under Devices and download its script bundle.",
			"Import the bundle on the router; it starts reporting and syncing immediately.",
			"Anything you release or whitelist here disappears from every router within one poll interval.",
		},
	},
	"addresses": {
		Key:   "addresses",
		Title: "The shared blocklist",
		Body: `<p>Every address your routers have reported. <strong>Blocked</strong> entries are on the
			routers right now. <strong>Released</strong> entries are kept for their history but are not
			enforced anywhere.</p>
		<p>Search accepts a partial address, a CIDR range such as <code>203.0.113.0/24</code>, a country
			name or code, or part of a network operator's name. Select rows to act on several at once;
			releasing or whitelisting reaches the routers on their next poll, typically within 15 seconds.</p>`,
		Steps: []string{
			"Sort by routers to find the addresses several sites have seen independently.",
			"Open a row to see exactly which router first reported it, and when.",
			"Whitelist rather than release when an address must never come back.",
		},
	},
	"address": {
		Key:   "address",
		Title: "One address in detail",
		Body: `<p>The timeline lists each router that has reported this address, when it first saw it and
			when it last did. Several routers reporting the same address at different sites is a much
			stronger signal than one router reporting it repeatedly.</p>`,
	},
	"whitelist": {
		Key:   "whitelist",
		Title: "Protecting addresses from being blocked",
		Body: `<p>A whitelist rule takes precedence over everything. Adding one immediately releases every
			blocked address it covers and tells all routers to drop them, and it stops those addresses
			being blocked again while the rule exists.</p>
		<p>Rules accept a single address or a CIDR range. Use <em>Preview</em> before saving to see exactly
			which currently blocked addresses a rule would release.</p>`,
		Steps: []string{
			"Add your own office and monitoring ranges here before anything else.",
			"Private, loopback and reserved ranges are rejected at ingest and never need a rule.",
			"A rule with an expiry disappears on its own; the addresses it covered stay released.",
		},
	},
	"devices": {
		Key:   "devices",
		Title: "Your routers",
		Body: `<p>Each router authenticates with its own token, so one compromised device can be revoked
			without touching the others. <strong>Online</strong> means the router has polled within four
			times its own interval.</p>
		<p><strong>Cursor</strong> is the position in the change log the router has acknowledged. If it
			lags well behind the server cursor the router is not keeping up; if it is empty the router has
			rebooted and is rebuilding its list.</p>`,
		Steps: []string{
			"Add a device, then open it and generate the install bundle.",
			"The token is shown once, inside the generated file. Losing it means issuing a new one.",
			"Import the bundle on the router with /import file-name=apb-install.rsc",
		},
	},
	"device": {
		Key:   "device",
		Title: "Device settings and scripts",
		Body: `<p>The list names, the entry timeout and the intervals are written into the scripts when
			a bundle is generated, so changing them here means generating and importing a new bundle.
			Only which addresses the router receives is decided by the server at run time.</p>
		<p><strong>Contributes</strong> lets the router upload what it detects. <strong>Receives</strong>
			lets it download the shared list. A router can do either, both or neither.</p>`,
	},
	"scripts": {
		Key:   "scripts",
		Title: "Generating the RouterOS files",
		Body: `<p>The bundle installs five scripts and three schedules. Blocklist entries are added with a
			timeout, which is what keeps them in RAM: nothing is ever written to the router's flash, and the
			list is rebuilt automatically after a reboot. RouterOS refuses a timeout longer than a couple of
			months and then holds nothing at all, so the default is four weeks; run
			<code>apb-test</code> on a router to find its own ceiling.</p>
		<p>Generating a bundle issues a fresh token that is embedded in the file. Previous tokens keep
			working until you revoke them, so you can roll a router over without an outage.</p>`,
		Steps: []string{
			"Review the preview below; it shows the exact script with the token masked.",
			"Download apb-install.rsc, upload it to the router, then run /import file-name=apb-install.rsc",
			"Delete the file from the router afterwards: it contains the token.",
			"The firewall example is not installed for you. Read it before importing.",
		},
	},
	"activity": {
		Key:   "activity",
		Title: "The raw report stream",
		Body: `<p>One line per address per report, newest first. <strong>New</strong> marks the first time
			any router reported that address. This view is the quickest way to confirm a newly installed
			router is actually sending data.</p>`,
	},
	"audit": {
		Key:   "audit",
		Title: "Administrative audit log",
		Body: `<p>Every sign in, every configuration change and every blocklist action taken from the
			console, with the account and address that made it. Router traffic is not logged here: it
			appears under Activity instead.</p>`,
	},
	"users": {
		Key:   "users",
		Title: "Console accounts",
		Body: `<p>Two-factor authentication is mandatory: a new account cannot reach anything until it has
			enrolled an authenticator. <strong>Owners</strong> can manage other owners,
			<strong>administrators</strong> can do everything else, and <strong>viewers</strong> can only
			read.</p>
		<p>If someone loses their authenticator, clear their second factor here; they will enrol a new one
			at their next sign in. The last active owner cannot be deleted, demoted or disabled.</p>`,
	},
	"settings": {
		Key:   "settings",
		Title: "How these settings behave",
		Body: `<p>Changes take effect immediately on the server. The defaults for new routers, and the
			entry timeout in particular, are written into a bundle when it is generated, so changing them
			only affects routers whose bundles you generate afterwards.</p>
		<p>The two corroboration settings are the important ones. Requiring reports from more than one
			router before an address is broadcast trades a little speed for a much lower chance of blocking
			something by accident.</p>`,
	},
	"account": {
		Key:   "account",
		Title: "Your account",
		Body: `<p>Changing your password signs out every session, including this one. Sessions expire on
			their own after the idle and absolute limits set under Settings.</p>`,
	},
}

// hintFor is exposed to templates so a page can render its own card.
func hintFor(key string) Hint { return hints[key] }

func (s *Server) postHintDismiss(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "malformed form submission")
		return
	}
	key := r.PostFormValue("hint")
	if _, ok := hints[key]; !ok {
		s.fail(w, r, http.StatusBadRequest, "unknown hint")
		return
	}
	if err := s.db.MarkHintSeen(r.Context(), sc.admin.ID, key); err != nil {
		s.log.Warn("dismiss hint", "err", err)
	}
	back := safeNext(r.PostFormValue("back"))
	if back == "" {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) postHintReset(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	if err := s.db.ResetHints(r.Context(), sc.admin.ID); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "could not reset the guidance")
		return
	}
	s.flash(sc, "ok", "The explainer cards will show again on every section.")
	http.Redirect(w, r, "/help", http.StatusSeeOther)
}

func (s *Server) getHelp(w http.ResponseWriter, r *http.Request, sc *sessionCtx) {
	order := []string{"dashboard", "addresses", "address", "whitelist", "devices",
		"device", "scripts", "activity", "audit", "users", "settings", "account"}
	list := make([]Hint, 0, len(order))
	for _, k := range order {
		list = append(list, hints[k])
	}
	s.render(w, r, sc, "help.html", "Help", "help", map[string]any{"Hints": list})
}
