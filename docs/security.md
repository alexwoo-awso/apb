# Security

## What this system is

A service that tells firewalls what to block. The interesting failure is not
someone reading the blocklist — it is someone *writing* to it, because an
attacker who can add an address can take you off the internet, and one who can
remove an address can quietly unblock themselves.

Everything below follows from that.

## Threat model

| Adversary | Can | Is stopped by |
|---|---|---|
| Internet scanner | reach the service | token on every router endpoint; optional User-Agent gate; rate limits |
| Someone with a stolen router token | report addresses as that router | corroboration thresholds; per-device revocation; bogon rejection; the token cannot read the console |
| Someone with a stolen console password | nothing on its own | mandatory TOTP, replay-protected |
| A malicious or broken router | flood reports | rate limit, batch size cap, corroboration threshold, and the whitelist it cannot override |
| Someone with the database file | read the blocklist and the audit log | TOTP secrets are encrypted; tokens and passwords are not recoverable |
| Someone who can intercept the router's traffic | replay or steal a token | TLS with certificate verification (see the RouterOS 6 caveat) |
| A curious administrator | read anything | roles; every mutation is audited |

## Credentials

**Console passwords** are argon2id at the OWASP low-memory profile: 19 MiB,
two passes, one lane. The only rule is a twelve-character minimum with a
rejection of trivially repetitive strings — length is what resists an offline
attack, and composition rules mainly produce predictable passwords.

**Two-factor authentication is mandatory.** An account that has not enrolled an
authenticator can reach its own enrolment page and nothing else. Codes are
RFC 6238, SHA-1, six digits, thirty seconds, with one step of tolerated drift
in each direction. The step a code belongs to is remembered per account, so a
code observed over someone's shoulder cannot be replayed during the ninety
seconds it stays arithmetically valid.

**Device tokens** are 160 bits of entropy. They are stored as HMAC-SHA256, not
as a password hash: there is nothing to brute force at that entropy, and
authentication has to be one indexed lookup on every fifteen-second poll from
every router. They are displayed exactly once.

**One master secret** (`APB_SECRET_KEY`, or `/data/secret.key`) is the root of
everything. Three independent subkeys are derived from it with HKDF: one seals
TOTP secrets with AES-GCM, one keys the token hash, one salts session
identifiers. Losing it invalidates every enrolment and every token at once;
`apbctl` can then rebuild both.

## Sessions

- The cookie carries 256 random bits; the database stores only its keyed hash.
- `HttpOnly`, `SameSite=Strict`, and `Secure` unless `APB_DEV` is set.
- Regenerated on every sign-in, so a session fixed beforehand is worthless.
- Two deadlines: idle (60 minutes by default) and absolute (12 hours).
- Invalidated everywhere on password change, role change and account disable.
- Every state-changing form carries a per-session CSRF token, compared in
  constant time.

Login failures are counted per account and lock it after a threshold, and are
independently rate-limited per client address and per username. Every failure
gives the same message whatever went wrong, so probing cannot distinguish a
wrong username from a wrong password from a locked account. An unknown username
still costs a password verification, so response time does not leak either.

## The browser

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none';
base-uri 'none'; object-src 'none'
```

No inline script, no inline style, no third-party origin, no CDN, no web font.
The console ships one stylesheet, about eighty lines of its own JavaScript, and
a world map generated at build time from public-domain geometry. There is no
supply chain to compromise because there are no front-end dependencies.

The no-inline-style rule is why proportional bars pick a width class rather than
setting `style="width:…"`, and why charts are rendered as SVG on the server.

Also set: HSTS (two years, subdomains), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, a restrictive
`Permissions-Policy`, and same-origin cross-origin policies.

## Input

Every address in the system passes through one function, and every SQL
statement lives in one package. Those two rules are what stop an injection or a
bad address having a second way in.

**Never blockable, whatever a router sends:** `0.0.0.0/8`, `10/8`, `100.64/10`,
`127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.88.99/24`,
`192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`,
`::/128`, `::1/128`, `64:ff9b::/96`, `100::/64`, `2001:db8::/32`, `fc00::/7`,
`fe80::/10`, `ff00::/8`.

Blocking any of those on a router is at best useless and at worst locks the
operator out of their own network, so it is refused at ingest rather than left
to a whitelist rule someone might forget.

Beyond that: prepared statements only, bodies capped before they are read,
`STRICT` tables so the database rejects a wrong type rather than storing it,
and foreign keys on.

## Generated scripts are code

A bundle is RouterOS code that runs with write privileges. A list name
containing a quote could break out of the string it is placed in, so the
generator **validates rather than escapes**: names must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,30}`, timeouts must look like `520w`, the
certificate mode must be one of three known values, intervals must be in range,
and the base URL must be a well-formed `https://` address. Anything else is
refused with an explanation.

Generating over plain HTTP is refused outright, because the token would cross
the network in clear text. The only exception is `APB_DEV`, for local work.

## The container

Distroless, non-root (65532), read-only root filesystem, all capabilities
dropped, `no-new-privileges`, a 16 MiB tmpfs for `/tmp`, and one writable
volume. There is no shell, no package manager and no interpreter in the image,
so a code-execution bug has nothing to pivot into. The health check is a mode of
the service binary rather than a bundled `curl`.

## Auditing

Every administrative action is recorded with the account, the target, the
client address and whether it succeeded: sign-ins and failures, settings
changes, device and token lifecycle, every blocklist and whitelist mutation,
every export. Router traffic is not in there — it would drown the log — and
appears under Activity instead.

## What is deliberately not protected against

- **A compromised administrator account with a working second factor.** It can
  do everything, by design. The audit log tells you what it did.
- **Traffic analysis.** Someone watching a router's connections learns it is
  talking to APB every fifteen seconds.
- **Reading the blocklist from a router.** Any token holder can download the
  whole list. It is a list of addresses that attacked someone; the value is in
  writing to it.
- **A determined denial of service.** Rate limits protect the database, not the
  network. Put a proxy in front of it.
- **RouterOS 6 without an imported CA.** The default there is unverified TLS,
  because verification-on-by-default would simply stop every v6 router from
  syncing. The console flags it and [routeros.md](routeros.md) explains the fix.

## Reporting a problem

Open an issue at <https://github.com/alexwoo-awso/apb/issues>. If it is
sensitive, say so and leave out the detail until someone can take it privately.
