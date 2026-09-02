# The router protocol

Everything a router does goes through four endpoints under `/api/v1`. The
format is plain text, chosen so a RouterOS script can decode it with one
`:toarray` call and no string surgery.

## Format

A response is a single line: comma-separated tokens, **no trailing newline**.
The first character of each token says what it is.

| Token | Meaning |
|---|---|
| `c<seq>` | the cursor to store, once everything else in the response has been applied |
| `+<addr>` | add this address to the blocklist |
| `-<addr>` | remove this address from the blocklist |
| `m1` | more changes are already waiting: poll again immediately |
| `r1` | your cursor predates the retained history; run a full rebuild |
| `n<id>` | during a full rebuild, the marker for the next page |

The trailing newline is omitted deliberately: `:toarray` would fold it into the
final token, and the router would try to add an address with a newline on the
end.

Every response is capped at `max_sync_bytes` (8 KB by default). `/tool fetch`
with `output=user as-value` truncates somewhere between 20 and 64 KB depending
on the build, and it does so silently — the script sees a short string, not an
error — so the cap is set well below any of those figures and continuation is
explicit.

## Authentication

```
Authorization: Bearer apb_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

One token per router. Tokens are 160 bits of entropy, stored as
HMAC-SHA256 under a key derived from the server secret, and shown exactly once
— when a script bundle is generated or a token is issued by hand.

A device can hold several valid tokens at once, which is how a router is rolled
over without an outage: issue the new one, install it, confirm the router is
syncing, then revoke the old one.

Unknown, revoked, expired and disabled-device tokens all produce the same
`401`, so probing cannot tell them apart.

If `require_user_agent` is set under Settings, requests must also carry that
exact `User-Agent`. It is a noise filter, not a control: it keeps background
internet scanning out of the logs before the token is even checked.

### Rate limits

- Unauthenticated attempts: 10 immediately, then one every two seconds, per
  client address.
- Authenticated traffic: 60 immediately, then four a second, per device. A
  router polling every 15 seconds uses about 0.07 requests a second, so this
  leaves ample headroom for catch-up loops while capping a runaway script.

Over the limit is `429` with `Retry-After`.

---

## `GET /api/v1/sync`

The steady-state call. Fetches everything that has changed since a cursor.

| Parameter | Meaning |
|---|---|
| `c` | the cursor the router currently holds; `0` means "from the beginning" |
| `n` | optional: how many entries the router is holding, for the health display |

```
GET /api/v1/sync?c=48213&n=51204

c48260,+45.83.64.7,+91.240.118.3,-203.0.113.9
```

Nothing to do — the overwhelming majority of calls:

```
c48260
```

More than one response worth of changes:

```
c48260,m1,+45.83.64.7,…
```

The router applies the operations, stores the cursor, and if `m1` was present
loops immediately rather than waiting for its next schedule.

Cursor too old to catch up:

```
r1
```

Within a single response, an address that was added and then removed appears
only once, carrying its final state. That is both correct and smaller.

## `GET /api/v1/full`

The rebuild path, used after a reboot or when the server answers `r1`.

| Parameter | Meaning |
|---|---|
| `a` | page marker from the previous response; omit for the first page |

The first page carries `c<seq>`, captured **before** the snapshot is read.
Anything that changes while the pages are being fetched is delivered again by
the delta stream afterwards, and applying it twice is harmless — so the cursor
is safe to adopt even though the download is not atomic.

```
GET /api/v1/full
c48260,n1053,+45.83.64.7,+45.83.64.8,…

GET /api/v1/full?a=1053
n2109,+45.83.65.1,…

GET /api/v1/full?a=8842
+45.83.99.7,…          ← no n token: this was the last page
```

A router with `ipv6` disabled receives only IPv4 addresses, here and in the
delta, so a v4-only script never sees an address it cannot add.

## `POST /api/v1/report`

Uploads locally detected addresses. The body is a plain list; commas,
newlines, spaces, tabs and semicolons all separate.

```
POST /api/v1/report
Content-Type: text/plain
X-Apb-Identity: edge-warsaw
X-Apb-Ros: 7.23.2 (stable)
X-Apb-Model: RB760iGS

45.83.64.7,91.240.118.3
```

```
ok,2,2,2,0,0,48262
   │ │ │ │ │ └── cursor after the batch
   │ │ │ │ └──── rejected: unparseable, private, reserved or otherwise unroutable
   │ │ │ └────── rejected: covered by a whitelist rule
   │ │ └──────── pushed to the routers by this batch
   │ └────────── addresses never seen before
   └──────────── accepted
```

The batch is one transaction: it lands completely or not at all, so a retry
after a timeout cannot leave half of it behind.

The three `X-Apb-*` headers are optional and let the console show what the
router calls itself. They are headers rather than query parameters because a
MikroTik identity may contain spaces and RouterOS cannot URL-encode.

Private, loopback, CGNAT, link-local, multicast, documentation and reserved
ranges are rejected here and can never reach a blocklist, whatever a router
sends.

## `GET /api/v1/whoami`

The router's server-side configuration, as one comma-separated line. This is
what makes the console's device settings take effect without regenerating any
scripts.

```
1,edge-1,APB,APB_detect,520w,15,300,0,1,1,48260,51204
```

| # | Field |
|---|---|
| 1 | format version |
| 2 | device name |
| 3 | blocklist address-list name |
| 4 | detection address-list name |
| 5 | entry timeout |
| 6 | sync interval, seconds |
| 7 | report interval, seconds |
| 8 | handles IPv6 |
| 9 | receives the blocklist |
| 10 | contributes detections |
| 11 | current server cursor |
| 12 | addresses currently on the list |

---

## Status codes

| Code | Means |
|---|---|
| `200` | fine; read the body |
| `401` | no token, wrong token, revoked, expired, or the device is disabled |
| `403` | the device is not allowed to contribute |
| `413` | report body over `max_report_size` |
| `429` | rate limited; `Retry-After` says how long |
| `500` | server side; the body starts `err,` |

## Health

`GET /healthz` needs no authentication and returns `ok` when the database is
reachable. It is what the container health check calls.

## Legacy compatibility

When `APB_LEGACY_UPLOAD` is on, the original endpoints are served as well:
`POST /up.php`, `GET /r/manifest` and `GET /r/snapshots/{add,rem}.csv`. They
share one credential across every router and cannot express removals, which is
exactly what this rework replaces. See [migration.md](migration.md).
