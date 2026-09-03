# Changelog

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
