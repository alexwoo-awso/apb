# Architecture

## Shape

One process. It serves two audiences on one port:

- `/api/v1/*` — the routers, authenticated by a per-device bearer token,
  speaking a line-oriented text protocol designed around what RouterOS scripts
  can parse cheaply.
- everything else — the web console, authenticated by a session cookie plus a
  mandatory second factor, rendered entirely on the server.

Behind both sits a single SQLite database in WAL mode, opened twice: one
connection for writes, a small pool for reads. SQLite allows many readers and
exactly one writer, so making that explicit removes a whole class of `database
is locked` surprises and keeps a slow report from blocking the dashboard.

```
                     ┌──────────────────────────── apbd ────────────────────────────┐
   routers ─────────>│ syncapi   ──┐                                                │
   (bearer token)    │             │                                                │
                     │             ├──> store ──> SQLite (WAL)  ──> /data/apb.db    │
   browsers ────────>│ adminui   ──┘        ^                                       │
   (session + TOTP)  │                      │                                       │
                     │ background: geo enrichment · expiry · retention · checkpoint │
                     └──────────────────────────────────────────────────────────────┘
```

## The change log is the whole design

Everything else follows from one table:

```sql
CREATE TABLE changes (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    op     TEXT NOT NULL,   -- A = add, R = remove
    ip     TEXT NOT NULL,
    family INTEGER NOT NULL,
    at     INTEGER NOT NULL
);
```

`AUTOINCREMENT` matters: it guarantees the sequence is monotonic and never
reuses a number, even after rows are deleted. A router's entire state is one
integer — the highest sequence it has applied. Synchronisation is then just
"give me everything above this number", which is:

- **cheap on the server**: an indexed range scan, and nothing to compute.
- **cheap on the router**: no diffing, no set comparison, no full list.
- **correct after a failure**: the router only advances its cursor after it has
  applied everything in the response, so an interrupted sync is retried, not
  lost.
- **cheap when idle**, which is almost always: the server answers with the
  cursor the router already has and nothing else, ten bytes or so.

### Why not respond with nothing when idle?

An empty body is fewer bytes, but some RouterOS builds dislike a zero-length
fetch response, and a bare cursor lets the router confirm it is actually in
step rather than inferring it from silence. Ten bytes every fifteen seconds is
under 60 KB a day.

### Retention and resynchronisation

The log is pruned on a schedule. Before deleting anything, the highest sequence
being removed is recorded as the *cursor floor*. A router arriving with a cursor
below that floor has provably missed changes, so it is told `r1` and rebuilds
from scratch rather than silently drifting. This is the only correctness-
critical part of retention, and it is why the floor is written before the delete
rather than after.

## Why entries carry a timeout

RouterOS stores an address-list entry in the configuration — on flash — unless
it has a timeout. Entries with a timeout live in RAM and disappear on reboot.
The original APB added entries without a timeout, so every blocked address was a
flash write, which is what caused trouble on devices with small or worn storage.

How long that timeout can be is branch-specific, and getting it wrong is not a
soft failure:

- **RouterOS 7** accepts up to 4 294 967 295 seconds. The default is `520w`,
  about ten years, which also sits below 536 870 911 seconds, above which
  RouterOS displays a timeout as `0sec` even though it still tracks it. Staying
  under that keeps `/ip firewall address-list print` readable.
- **RouterOS 6** refuses anything beyond roughly 49 days — `2^32` milliseconds,
  consistent with a 32-bit millisecond field. Measured on 6.49.20: `4w` is
  accepted and `52w` is refused. It does not clamp the value, it rejects the
  entry, so a v6 router given `520w` runs the scripts and holds nothing. The
  default there is `4w`, and the generator refuses a longer one.

The shorter v6 window is covered by drift detection rather than by the timeout:
every sync carries the number of entries the router is holding, and a router
that is caught up by cursor but holding fewer addresses than the server has is
told to rebuild. Expiry, a manual flush and a half-finished rebuild all look the
same from the changelog's point of view, and all are caught the same way.

The timeout is a safety net, not the mechanism: the server is the source of
truth and removals arrive within one poll interval. The timeout only decides how
long a router cut off from the server keeps protecting itself — ten years on
RouterOS 7, four weeks on RouterOS 6.

Because the list is volatile, the router's cursor must be volatile too — they
have to be lost together or they disagree, and a cursor that outlived an empty
list would leave the router believing it was up to date while protecting
nothing.

The cursor is held in a RouterOS `:global` and mirrored to an address-list
marker that also carries a timeout. The global alone was the original design and
it did not work: on the 6.49 router this was first deployed to, the global did
not survive from one scheduled invocation to the next, so every poll saw no
cursor and ran a full rebuild. The marker is the authoritative copy; the global
is a cache. Both are RAM only, so a reboot clears them together with the list,
the sync script sees no cursor, and the bootstrap script rebuilds. No flag, no
state file, no special case.

## Corroboration

An address is recorded the moment it is reported, but it is only appended to the
change log — and therefore only reaches the routers — once it meets both
thresholds under Settings:

- **reports** — how many sightings in total.
- **distinct routers** — how many different devices.

With both at 1 the system behaves like the original: one router says so, and
everyone blocks. Raising the router threshold to 2 means a single misconfigured
device cannot blocklist a customer's mail server for the whole estate. The cost
is latency: the address waits for a second site to agree.

Per-device attribution is kept in one row per `(address, device)` pair, carrying
first-seen, last-seen and a count. That is what answers "which routers saw this,
and when did each of them first see it" without storing an unbounded event per
sighting. A separate, pruned event stream feeds the activity view and the hourly
charts.

## The whitelist wins

A whitelist rule is stored as an inclusive 16-byte range, so containment is a
`BETWEEN` on an indexed column rather than a scan with per-row CIDR maths. IPv4
addresses are stored in their IPv4-mapped 16-byte form, which gives one ordering
that works for both families.

Adding a rule does three things in one transaction: it stores the rule, it
releases every blocked address inside the range, and it appends a removal for
each of them. Ingest checks the whitelist before it records anything, so a
whitelisted address cannot come back through the front door either.

## Response sizing

`/tool fetch ... output=user as-value` truncates somewhere between 20 and 64 KB
depending on the build, and it truncates *silently* — the script sees a short
string, not an error. Every response is therefore capped at `max_sync_bytes`
(8 KB by default) and carries an explicit continuation marker:

- a delta that hits the cap sets `m1`, and the script loops immediately instead
  of waiting for its next schedule.
- a full rebuild page that hits the cap returns `n<id>`, and the script asks for
  the next page.

Both loops are bounded in the script, so a server bug cannot spin a router.

## What runs in the background

| Every | Does |
|---|---|
| 20s | resolves country and network for newly seen addresses |
| 1h | expires addresses and whitelist rules, prunes history, checkpoints the WAL |
| 24h | refreshes the geolocation databases, if enabled |

Geolocation is deliberately *not* on the ingest path. A router's report must
never wait on an MMDB lookup, let alone a download.

## Package layout

| Package | Holds |
|---|---|
| `internal/store` | every SQL statement, the migrations, the settings cache |
| `internal/model` | the plain types shared by all layers |
| `internal/netutil` | address parsing, the bogon list, CIDR ranges |
| `internal/syncapi` | the router protocol and the legacy shim |
| `internal/adminui` | the console: handlers, templates, the map, the explainers |
| `internal/auth` | argon2id, TOTP, sealed secrets, tokens |
| `internal/rsc` | the RouterOS script generator and its templates |
| `internal/geo` | MMDB lookups and updates |
| `internal/httpx` | middleware: real IP, security headers, logging, rate limits |

No package outside `store` writes SQL, and no package outside `netutil` parses
an address. Those two rules are what keep an injection or a bogon from having a
second way in.
