# APB

A shared abuse blocklist for MikroTik RouterOS. Your routers report the sources
that attack them, APB merges those reports into one list, and every router gets
the merged list back within seconds.

One static Go binary, one SQLite file, one container. No database server, no
message broker, no JavaScript build step, and nothing written to your routers'
flash.

```
   router A ──report──┐                    ┌──sync──> router A
   router B ──report──┼──>  APB  ──────────┼──sync──> router B
   router C ──report──┘   (merge,          └──sync──> router C
                           corroborate,
                           whitelist)
```

## What it does

- **Collects** the addresses your firewall rules have already flagged, from as
  many routers as you like, each with its own credential.
- **Corroborates** them. You choose how many separate routers must have seen an
  address before it is pushed to everyone.
- **Distributes** additions and removals through an append-only change log that
  routers follow with a cursor. Default propagation is 15 seconds.
- **Withdraws** cleanly. Releasing or whitelisting an address removes it from
  every router on their next poll — the thing the original design could not do.
- **Explains itself.** Every section of the console opens with a short
  explanation of what it does the first time you visit it.

### Entries live in RAM, not flash

This is the reason for the rework. RouterOS writes an address-list entry to
flash unless it carries a timeout; entries *with* a timeout are held in memory
and dropped on reboot. Everything APB adds carries a timeout, so a router
accumulating a hundred thousand blocked addresses never touches its flash.

**How long that timeout can be is limited, on both branches.** RouterOS refuses
a long address-list timeout, and it refuses the *entry* rather than clamping the
value — so a router given too large a number imports the bundle, runs it,
reports a clean rebuild, and holds nothing at all. Measured on real hardware:

| | 1d | 4w | 6w | 7w | 8w | 52w | 520w |
|---|---|---|---|---|---|---|---|
| RouterOS 6.49.20 | ok | ok | | | | refused | refused |
| RouterOS 7.x | ok | ok | ok | ok | ok | refused | refused |

Each device gets the longest value proven to work on its branch: **`4w` on
RouterOS 6, `8w` on RouterOS 7.** The generator refuses more than `8w`, nothing
above that having worked anywhere. Run `/system script run apb-test` on a router
to find its own ceiling — RouterOS 6 is only proven to `4w` because the finer
probes did not exist when the 6.49 device was measured, so it may well take
more.

If a router does refuse the timeout it will store nothing while every other
signal looks like success, so the scripts now count what they were sent against
what they kept and say so explicitly.

MikroTik's documentation gives a maximum of 4294967295 seconds. That figure does
not describe this field: a 7.x router refuses 52w. Trust the probe, not the
manual — and not this table either, if your hardware disagrees with it.

A four-week window is not a hole. The server compares what each router reports
holding against what it should hold, and tells a router whose list has drifted
to rebuild, so an expired entry is recovered exactly as a manual flush is. The
timeout only governs how long a router *cut off from the server* keeps
protecting itself.

A reboot therefore leaves the router with an empty list and no cursor. That is
the expected state, and the `apb-bootstrap` script detects it and rebuilds the
whole list from a paged download before the incremental sync resumes.

## Quick start

```sh
cp .env.example .env          # set APB_BASE_URL and APB_HOST
docker compose up -d
docker compose logs apb       # note the one-time setup code
```

Open `https://your-host/setup`, enter the code, create the first
administrator and enrol an authenticator. Then:

1. **Devices → Register a router.** Give it a name.
2. **Generate scripts → apb-install.rsc.** The file contains a freshly issued
   token; treat it as a password.
3. On the router: upload the file, then `/import file-name=apb-install.rsc`.
4. `/log print where message~"APB"` should show a rebuild completing within
   seconds, and the console shows the router as online.
5. Add enforcement rules. The generated `apb-firewall-example.rsc` is a
   starting point — read it before importing, because rule order matters.

Without Docker:

```sh
make build                    # bin/apbd and bin/apbctl
APB_DATA_DIR=./data APB_BASE_URL=https://apb.example.org ./bin/apbd
```

## What gets installed on a router

Four scripts and three schedules, all prefixed `apb-`:

| Script | Runs | Does |
|---|---|---|
| `apb-sync` | every 15s | applies the delta since the cursor held in RAM |
| `apb-bootstrap` | at startup, and on demand | rebuilds the whole list in pages |
| `apb-report` | every 5m | uploads new entries from the detection list |
| `apb-purge` | manually | clears everything APB manages here |

The scripts hold no state on disk. The replication cursor is held in a `:global`
and mirrored to an address-list marker carrying a timeout, because a RouterOS
global did not survive between scheduled runs on the 6.49 router this was first
deployed to; the "already reported" marker is a third address list, also with a
timeout. All of it is RAM only and all of it is lost on reboot, which is exactly
when it should be.

`/api/v1/whoami` reports a device's server-side configuration and `apb-test`
prints it, but the operational scripts do not yet read it: the list names, the
timeout and the intervals are baked in when the bundle is generated. **Changing
any of them in the console requires regenerating and reinstalling the bundle.**
Only which addresses are sent is decided by the server at run time.

## The protocol

Plain text, one comma-separated token stream, no trailing newline — the one
shape RouterOS decodes for free with a single `:toarray`.

```
GET /api/v1/sync?c=48213&n=51204
  → c48260,+45.83.64.7,+91.240.118.3,-203.0.113.9,m1

GET /api/v1/full            (after a reboot; paged)
  → c48260,n1053,+45.83.64.7,+...

POST /api/v1/report         body: 45.83.64.7,91.240.118.3
  → ok,2,2,2,0,0,48262

GET /api/v1/whoami
  → 1,edge-1,APB,APB_detect,4w,15,300,0,1,1,48260,51204
```

| Token | Meaning |
|---|---|
| `c<seq>` | cursor to remember once everything else has been applied |
| `+<addr>` | add to the blocklist |
| `-<addr>` | remove from the blocklist |
| `m1` | more changes are waiting; poll again now rather than in 15s |
| `r1` | cursor is older than the retained history; run a full rebuild |
| `n<id>` | next page marker during a full rebuild |

Every response is capped (8 KB by default) so it fits inside the buffer
`/tool fetch` hands to a script, which truncates well before 64 KB.

Authentication is a per-device bearer token, stored as a keyed hash and shown
exactly once. Revoking one router does not disturb the others.

## Security

- Argon2id passwords and mandatory TOTP; secrets sealed with AES-GCM under a
  key derived from one master secret.
- Session identifiers stored hashed, rotated on sign-in, with idle and absolute
  deadlines; CSRF tokens on every mutation; roles enforced server-side.
- Content Security Policy of `default-src 'none'` with no inline script or
  style and no third-party origin — the console ships its own CSS, its own
  ~80 lines of JavaScript, and a world map generated at build time.
- Private, loopback, CGNAT, documentation and reserved ranges are rejected at
  ingest and can never reach a blocklist.
- Generated scripts are validated before they are rendered: a list name or
  timeout that could break out of a RouterOS string is refused, not escaped.
- The container is distroless and non-root, with a read-only root filesystem,
  every capability dropped and `no-new-privileges` set.

See [docs/security.md](docs/security.md) for the full picture, including what
is deliberately *not* protected against.

## Documentation

| | |
|---|---|
| [docs/architecture.md](docs/architecture.md) | how the pieces fit together and why |
| [docs/api.md](docs/api.md) | the router protocol in full |
| [docs/routeros.md](docs/routeros.md) | the client scripts, detection rules, troubleshooting |
| [docs/operations.md](docs/operations.md) | backups, upgrades, sizing, recovery |
| [docs/security.md](docs/security.md) | threat model and controls |
| [docs/migration.md](docs/migration.md) | moving from the original APB |

## Administration without the console

`apbctl` talks to the database directly, so it works when nobody can sign in:

```sh
docker compose exec apb /apbctl admin list
docker compose exec apb /apbctl admin reset-2fa --username alex
docker compose exec apb /apbctl device token --name edge-1
docker compose exec apb /apbctl backup /data/apb-backup.db
```

## Development

```sh
make test      # unit tests plus a full end-to-end pass over the console
make lint      # go vet and gofmt
make run       # local server on :8080 over plain HTTP
make sample    # write example RouterOS bundles to bin/sample for review
```

## Licence

MIT. See [LICENSE](LICENSE).

The bundled world map is derived from Natural Earth (public domain) via the
[world-atlas](https://github.com/topojson/world-atlas) project and is
regenerated with `make worldmap`.
