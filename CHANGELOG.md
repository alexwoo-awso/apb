# Changelog

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
