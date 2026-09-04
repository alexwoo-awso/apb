# Changelog

## 2.1.3 — 2026-09-04

### Fixed

- **A steady-state poll now logs nothing.** The cursor recovery notice was
  emitted on every single run — four times a minute, for ever — because a
  RouterOS global does not survive between scheduled runs and the address-list
  marker is therefore always the source. It was a diagnostic added to find that
  out, it did its job, and it is now at `debug`.

The scripts speak only when something changes or fails: addresses applied, a
rebuild finished, a report uploaded at `info`; a failed request or a rejected
report at `warning`; a rebuild that gave up, or a router that received addresses
and stored none, at `error`.

A test now lists every message the sync script may log at `info` and fails on
any other, so adding one is a deliberate decision rather than an accident.

### Documented

- RouterOS 7 logs `fetch,info Download from ... FINISHED` for every request,
  which a script cannot suppress. `docs/routeros.md` now gives the logging rule
  that silences it, with the caveat that it applies to every script on the
  router.

## 2.1.2 — 2026-09-04

### Changed

- **Each device now gets the longest entry timeout proven to work on its
  RouterOS branch**, rather than one conservative value for both: `4w` on
  RouterOS 6, `8w` on RouterOS 7. Leaving the global default empty selects the
  per-branch maximum; an override is applied only where that branch is known to
  accept it, so a default suited to RouterOS 7 cannot silently break every
  RouterOS 6 device added afterwards.
- RouterOS 6 is proven only to `4w` because the finer probes did not exist when
  the 6.49 device was measured. It may well accept more; `apb-test` will say.

### Added

- **The scripts now count what they were sent against what they kept.** A router
  that refuses the entry timeout stores nothing while the fetch, the cursor and
  the rebuild message all look like success — the combination that hid this for
  nine releases. Both `apb-sync` and `apb-bootstrap` now log the mismatch and
  name the timeout being refused, with the fix.
- The device page warns when a timeout exceeds what its branch is proven to
  accept. It warns rather than refuses, since an operator may have measured
  further with `apb-test`.

## 2.1.1 — 2026-09-03

**The address-list timeout ceiling is a RouterOS property, not a RouterOS 6
one.** 2.1.0 shipped on the assumption that RouterOS 7 accepted the documented
maximum of 4294967295 seconds and so could keep the ten-year default. A 7.x
router refuses `52w` exactly as a 6.49 one does.

Measured on real hardware:

| | 1d | 4w | 6w | 7w | 8w | 52w | 520w |
|---|---|---|---|---|---|---|---|
| RouterOS 6.49.20 | ok | ok | | | | refused | refused |
| RouterOS 7.x | ok | ok | ok | ok | ok | refused | refused |

The `2^32` millisecond theory in 2.1.0 was also wrong: that predicts about 49.7
days, and 8w is 56 days and works. No replacement theory is offered here. The
generator caps at `8w`, the largest value observed to work anywhere, and
`apb-test` walks a ladder up to 52w so an operator can measure their own build.

### Changed

- Every device defaults to a `4w` entry timeout, on both branches. The cap is no
  longer conditioned on the RouterOS version.
- **A ten-year expiry is not achievable on any RouterOS branch tested.** The
  original brief asked for one; it cannot be delivered as specified, and the
  documentation now says so instead of quoting a figure from the manual.

### Fixed

- **The documentation claimed changing a device's settings took effect without
  regenerating its bundle. It does not.** No operational script consumes
  `/api/v1/whoami`: the list names, the entry timeout and the intervals are
  written into the scripts when a bundle is generated. Only which addresses a
  router receives is decided at run time. The README, the API reference, the
  RouterOS guide, the device page and two explainer cards all said otherwise.

## 2.1.0 — 2026-09-03

**RouterOS 6 cannot hold a ten-year address-list timeout.** Measured on a
6.49.20 hEX S: `1d`, `4w` accepted; `52w`, `520w` refused. The boundary is
`2^32` milliseconds, about 49.7 days, consistent with a 32-bit millisecond
field. RouterOS 7 accepts up to 4294967295 seconds and is unaffected.

This invalidates a claim made throughout the previous documentation, which
described `520w` as safe on the strength of RouterOS 7 material. It is not safe
on RouterOS 6, and the failure is silent in the worst way: the router imports
the bundle, runs it, logs a successful rebuild, and holds nothing at all,
because every individual `address-list add` is refused.

### Changed

- New RouterOS 6 devices default to a `4w` entry timeout; RouterOS 7 keeps
  `520w`. The generator now refuses a v6 bundle whose timeout exceeds 49 days
  rather than emitting one that cannot work.
- The README, the architecture notes, the RouterOS guide and the settings help
  all corrected. They previously stated the ten-year figure without
  qualification.
- The cursor description was also stale: it has been held in an address-list
  marker as well as a global since 2.0.6, because the global did not survive
  between scheduled runs.

### Added

- `apb-test` walks a finer ladder — 1d, 4w, 6w, 7w, 8w, 52w, 520w — so an
  operator can find their own build's ceiling and set the device's entry timeout
  to the largest value that works. Changing it needs no regeneration.

### Why the shorter window is not a hole

Entries on a RouterOS 6 router now expire after four weeks. Drift detection,
added in 2.0.8, covers this: every sync carries the number of entries the router
holds, and a router that is caught up by cursor but holding fewer addresses than
the server has is told to rebuild. Expiry, a manual flush and a half-finished
rebuild are indistinguishable from the changelog's point of view and are all
caught the same way. The timeout only governs how long a router *cut off from
the server* keeps protecting itself: ten years on v7, four weeks on v6.

## 2.0.8 — 2026-09-03

A RouterOS 6.49 router refuses every `address-list add ... timeout=` the
scripts issue. That operation is the basis of the whole design — a timeout is
what keeps an entry in RAM rather than on flash — and it had never executed on
that router, because the blocklist was empty for every attempt so far.

### Changed

- The timeout is written as a literal rather than passed through a RouterOS
  variable. That was one of two candidate causes and is what a person would type
  at the CLI, so it removes a conversion step that cannot be observed from
  inside a script.

### Added

- `apb-test` now walks a ladder of address-list writes that varies one thing at
  a time — the address, the size of the timeout, and literal versus variable —
  so a refusal is attributed rather than guessed at. The largest value that
  reports OK is the one to set as the device's entry timeout.
- **Drift detection.** A router can lose entries behind the server's back: a
  timeout expires, an operator flushes the list, a rebuild half-finishes. The
  cursor cannot see any of that, because by the changelog the device is up to
  date. The count each router already reports is now compared against what it
  should hold, and a device that is caught up but short is told to rebuild, at
  most once every fifteen minutes so a router that cannot hold the list is not
  put in a loop. This makes a short entry timeout survivable rather than a
  silent hole.

## 2.0.7 — 2026-09-03

### Fixed

- **Recording the cursor failed, and said only that it had failed.** The removal
  of the previous marker and the write of the new one shared one guarded block,
  so whichever failed produced the same message and skipped the other. RouterOS
  errors on a removal that matches nothing, and on the first run the state list
  does not exist, which aborted the block before anything was written. The two
  operations are now separate, each reporting itself, and the removal only runs
  when there is something to remove.
- The marker uses `192.0.2.1`, a documentation address that cannot be confused
  with a real target, instead of `0.0.0.1`.

### Added

- `apb-test` now probes the address-list write directly, in a throwaway list:
  an entry with a timeout and a comment, one without a comment, a removal of a
  list with entries, and a removal of one already empty. Every probe carries a
  timeout, so the diagnostic itself can never write to the router's flash.

## 2.0.6 — 2026-09-03

### Fixed

- **The replication cursor did not survive between scheduler runs.** It lived
  only in a RouterOS `:global`, and on a real 6.49 router that global was gone
  by the next invocation fifteen seconds later. Every poll therefore saw no
  cursor, ran a full rebuild, and never reached the incremental sync at all.
  The cursor is now also written to an address-list marker, which is ordinary
  router state and persists exactly as the blocklist does. It carries a timeout,
  so like everything else this project installs it lives in RAM and disappears
  on reboot, which is precisely when the cursor should be lost.
- **The rebuild reported success it had not verified.** It logged the cursor the
  server sent rather than the one the router stored, so a cursor that never
  persisted looked identical to one that did. It now reports what it holds.
- **A device rebuilding its list showed as "never synced".** Liveness was
  recorded only on `/sync`, so a router calling `/full` every fifteen seconds
  filled the server log while the console insisted it had never been in touch.
  Any authenticated request now counts as contact.

## 2.0.5 — 2026-09-03

### Fixed

- **Adding a custom header stopped RouterOS 6 making the request at all.** The
  `X-Apb-Agent` header introduced in 2.0.4 made `/tool fetch` fail before it
  left the router, so requests that previously arrived and were merely rejected
  stopped arriving entirely. The client identity now travels in the query
  string, which the script composes as part of the URL and no HTTP client can
  interfere with, and the generated scripts are back to the two headers proven
  to reach the server: `Authorization` and `User-Agent`.
- The server accepts the identity from the `k` query parameter, the
  `X-Apb-Agent` header, or any `User-Agent`, so a client that can set headers
  freely is not forced to use a URL.
- **The response budget undercounted.** `max_sync_bytes` was applied to address
  text only, ignoring each entry's operation marker and separator, so a page
  measured 8911 bytes against a stated 8192. Harmless at the default, but a
  raised setting would have crept toward the size at which `/tool fetch`
  silently truncates. The budget now covers the whole response.
- Report metadata headers are sent only on RouterOS 7, since custom headers are
  what broke the fetch on 6.

### Changed

- The client identity must now be letters, digits, dot, dash or underscore: it
  appears in a URL and RouterOS cannot percent-encode. Generation fails with an
  explanation rather than producing corrupted requests.
- `apb-test` now probes four header shapes and logs which ones this RouterOS
  build accepts, so a header problem is measured rather than guessed at.

**Regenerate and reinstall any bundle produced before this release.**

## 2.0.4 — 2026-09-03

### Fixed

- **The client identity gate could never be satisfied on RouterOS 6.** RouterOS
  sets its own `User-Agent` and does not let a script override it through
  `http-header-field`: a v6 router sends `Mikrotik/6.x Fetch` whatever the
  script asks for, so a configured gate rejected every request forever. The
  generated scripts now send the value in a dedicated `X-Apb-Agent` header,
  which RouterOS has no opinion about and passes through verbatim, and in a
  lowercase `user-agent` entry, which is the form that demonstrably reached the
  server on this RouterOS version. The gate accepts either.
- The rejection log names both headers it looked in, not just one.

### Changed

- The setting is now labelled "Required client identity", because it is no
  longer only about `User-Agent`.

**A bundle generated before this release sends only `User-Agent` and will be
rejected on RouterOS 6 whenever the gate is set. Regenerate it, or leave the
setting empty.**

## 2.0.3 — 2026-09-03

### Fixed

- **A User-Agent mismatch was undiagnosable.** The gate rejected with the same
  bare 401 a bad token produces, and logged only `reason: user-agent`. The log
  now names the value expected, the value received, and how to recover. This
  setting is the one most able to take an estate offline — its value is baked
  into a bundle when that bundle is generated, so changing it silently rejects
  every router still running an older bundle — and it was the least explicable
  failure in the system.
- The gate now matches against every `User-Agent` header rather than only the
  first, so a client that appends its own identity alongside the one a script
  asked for is not rejected for a header it did send.

### Changed

- The Devices page shows a warning whenever the gate is active, naming the
  required value and what to do about routers that predate it.
- The script generation page states which User-Agent the bundle will carry.
- The setting's own help text now leads with the consequence of changing it.

## 2.0.2 — 2026-09-03

### Fixed

- **Every fetch failed on RouterOS 6.** `/tool fetch` defaults to `mode=http`
  and accepts `check-certificate` only in https mode, so an https endpoint with
  no explicit mode failed on both counts: the wrong transport, and a parameter
  that is not valid for it. The router logged nothing but
  `APB: rebuild failed, the sync script will retry` in a loop and never reached
  the server. Every fetch now carries a `mode=` derived from the configured base
  URL, and `check-certificate` is emitted only where it is legal.
- **The error handling hid the cause.** A failed fetch set a flag and produced
  one generic message. Each failure path now says what it was doing and what
  came back: the URL it could not reach, the fetch status it got, or that the
  reply was empty.

### Added

- **`apb-test`**, a one-shot connectivity check installed with every bundle and
  deliberately not scheduled. Run `/system script run apb-test` and read
  `/log print where message~"APB test"`: it reports the transport it used, the
  fetch status, the server's raw reply, and whether the token was accepted. It
  turns a silent retry loop into a single readable answer.

A test now asserts that every `/tool fetch` in a generated bundle carries the
transport mode, and that `check-certificate` appears only for https endpoints.

**Regenerate and reinstall any bundle produced by 2.0.0 or 2.0.1.**

## 2.0.1 — 2026-09-03

### Fixed

- **Generated RouterOS bundles failed to import.** The generator used
  MikroTik's own export format, which continues long lines with a trailing
  backslash. That format is not safe to move between machines: the continuation
  is a backslash followed by a newline, so a file that acquires CRLF line
  endings in transit — a download on Windows, an editor, a copy-paste — puts a
  carriage return after the backslash, the line stops continuing, the quoted
  `source="` string is left open, and `/import` fails several lines later with
  `expected end of command`. Reported on RouterOS 6.49.20.
- **Generated scripts could be silently corrupted.** RouterOS strips leading
  whitespace on a continuation line, so a line break placed immediately before a
  space ate a space that belonged to the script. Eight such breaks were present
  in a typical bundle, one of them turning `:local Hdr (...)` into
  `:local Hdr(...)`, which would have failed at run time even if the import had
  succeeded.

Script bodies are now assembled one piece at a time into a variable and then
installed, so every line of a generated file is a complete command and the file
imports identically with LF or CRLF endings. Three tests lock this in: no
generated line may end with a backslash, the bundle must survive CRLF
conversion, and the assembled source must match the template byte for byte.

Removals of previous installations now target each script and schedule by name
rather than by regular expression, and no longer use an empty `on-error` block.

**Regenerate and reinstall any bundle produced by 2.0.0.**

## 2.0.0 — 2026-09-02

A complete rewrite. The original PHP and cron stack is replaced by a single Go
binary; the RouterOS side is replaced entirely.

### The reason for the rewrite

- **Address-list entries no longer touch flash.** Every entry is added with
  `timeout=520w`, which RouterOS holds in RAM. The old scripts added entries
  without a timeout, so each one was written to the router's configuration and,
  on some devices, wore out or filled the storage.
- **Removals work.** The old `rem.csv` existed but nothing ever wrote to it, so
  an address could be blocked but never unblocked. Releasing or whitelisting an
  address now reaches every router within one poll interval.
- **Recovery after a reboot.** Because the list is volatile, a new bootstrap
  script rebuilds it from a paged download at startup, in seconds.

### Distribution

- Replication is an append-only change log with a monotonic cursor. Routers poll
  a delta endpoint every 15 seconds by default, down from an hour.
- The idle response is about ten bytes; a busy one is capped so it always fits
  inside the buffer `/tool fetch` gives a script.
- Text protocol designed for one `:toarray` call, no line splitting.

### Security

- One bearer token per router, stored hashed, shown once, revocable
  individually. The old shared HTTP Basic credential is gone.
- Console accounts with argon2id passwords and mandatory, replay-protected TOTP.
- Roles, per-session CSRF tokens, hashed session identifiers, idle and absolute
  session deadlines, login lockout and rate limits.
- Content Security Policy of `default-src 'none'` with no inline script or
  style and no third-party origin.
- Private, loopback, CGNAT, documentation and reserved ranges are rejected at
  ingest and can never reach a blocklist.
- Generated scripts are validated rather than escaped: a name or timeout that
  could break out of a RouterOS string is refused.
- Distroless non-root container, read-only root filesystem, all capabilities
  dropped.

### Console

- Dashboard with an offline world map, hourly activity chart, top countries,
  top networks and router health.
- Blocklist with search across address, CIDR, country and network operator;
  bulk release, whitelist, re-block and delete; CSV and plain-list export.
- Per-address history showing which routers reported it and when each first saw
  it.
- Whitelist with a preview of exactly what a rule would release before saving.
- Device provisioning, token lifecycle, and a script generator with a preview.
- Administrator management, settings, activity stream and audit log.
- Every section opens with an explanation the first time an account visits it.

### Operations

- `apbctl` for administration that does not depend on being able to sign in.
- `import-legacy` loads the old CSV files with full validation.
- Optional compatibility endpoints keep unconverted routers reporting during a
  migration.
- Optional local geolocation using open-licensed MaxMind-format databases. No
  address is ever sent to a third party.
