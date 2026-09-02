# Operations

## Sizing

| Blocklist | Database | Server memory | Router memory |
|---|---|---|---|
| 10 000 | ~5 MB | ~30 MB | ~1.5 MB |
| 100 000 | ~45 MB | ~60 MB | ~15 MB |
| 500 000 | ~220 MB | ~120 MB | ~70 MB |

The container idles at about 6 MB and the compose file caps it at 256 MB, which
is comfortable well past half a million addresses. Router memory is the real
constraint: budget 100–150 bytes per address-list entry and check
`/system resource print` on your smallest device before letting the list grow.

Traffic per router is negligible. A fifteen-second poll that finds nothing
transfers around ten bytes of body, so roughly 60 KB of body a day plus TLS
overhead.

## Backups

The database is one file, but copying it while the service runs is not safe.
Use the built-in consistent copy:

```sh
docker compose exec apb /apbctl backup /data/backup-$(date +%F).db
docker compose cp apb:/data/backup-$(date +%F).db ./
```

**Also back up the secret**, `/data/secret.key`, or whatever you set
`APB_SECRET_KEY` to. Without it the database is still readable but every TOTP
enrolment and every device token is dead, and you will be re-provisioning every
router by hand.

A nightly cron on the host:

```sh
0 3 * * * docker compose -f /opt/apb/docker-compose.yml exec -T apb \
  /apbctl backup /data/backup-$(date +\%F).db && \
  find /var/lib/docker/volumes/apb_apb-data/_data -name 'backup-*.db' -mtime +14 -delete
```

## Restoring

```sh
docker compose down
# put apb.db and secret.key back into the volume
docker compose up -d
```

Routers reconnect on their own. Any whose cursor is now ahead of the restored
log gets `r1` on its next poll and rebuilds — no intervention needed.

## Upgrading

```sh
git pull
docker compose up -d --build
```

Migrations run automatically at startup and are recorded in
`schema_migrations`. Take a backup first if the release notes mention a schema
change. Routers keep polling through the restart and retry what they miss.

## Health

- `GET /healthz` — unauthenticated, returns `ok` when the database answers.
  This is what the container health check uses.
- **Settings → Service** shows the database size, the replication cursor and a
  SQLite integrity check.
- **Devices** shows each router's state, its cursor lag and when it last synced
  or reported.

A router is *online* if it has polled within four times its own interval,
*lagging* up to ten times that, and *offline* beyond it.

## Routine maintenance

Runs hourly on its own: expiring addresses and whitelist rules, pruning the
change log, the activity stream, the audit log and dead sessions, and
checkpointing the WAL. Force a pass with:

```sh
docker compose exec apb /apbctl maintain
```

The retention settings that matter:

- **Replication log** (30 days). A router offline for longer rebuilds its whole
  list instead of catching up. Lower it to save space, raise it if you have
  routers that go away for a month.
- **Activity stream** (30 days) — the raw per-report feed.
- **Audit log** (180 days) — administrative actions.

## Getting back in

Locked out of the console, `apbctl` still works because it talks to the
database directly:

```sh
# lost authenticator
docker compose exec apb /apbctl admin reset-2fa --username alex

# forgotten password
docker compose exec apb /apbctl admin passwd --username alex

# too many failed sign-ins
docker compose exec apb /apbctl admin unlock --username alex

# no accounts at all
docker compose exec apb /apbctl admin create --username alex --owner
```

A password reset signs out every session for that account. A 2FA reset does too,
and the account enrols a new authenticator at its next sign-in.

If no administrator exists at startup, the service prints a one-time setup code
and `/setup` becomes reachable. Read it with `docker compose logs apb`.

## Geolocation

Optional. Blocking works without it; you lose countries, network operators and
the map.

**Settings → Geolocation databases → Download now** fetches an open-licensed
country and ASN database in MaxMind format — no account, no key. The download
is validated as a real MMDB before it replaces a working file, and a failed
download leaves the existing one alone.

To use a file you already have, drop `country.mmdb` and `asn.mmdb` into
`/data/geo` and press **Reload from disk**. Any MaxMind-format database works,
including paid ones; point the URLs wherever you like.

Lookups are local. No address APB handles is ever sent anywhere.

## Tuning propagation

The default is a fifteen-second poll, so a block reaches every router within
fifteen seconds and a release does too.

- **Faster**: lower the interval per device. Five seconds is the floor. Each
  poll is a TLS handshake, so on older hardware without crypto acceleration
  watch the router's CPU before going below ten.
- **Cheaper**: raise it. Sixty seconds costs a quarter of the handshakes and is
  still far better than the hourly cycle this replaced.

Change it on the device page. The router picks it up on its next run — the
scripts ask the server for their configuration, so nothing needs regenerating.

## Reading the logs

Structured JSON by default; set `APB_LOG_FORMAT=text` for a console.

```sh
docker compose logs -f apb
docker compose logs apb | grep -F '"level":"ERROR"'
docker compose logs apb | grep -F 'device request rejected'   # bad tokens
docker compose logs apb | grep -F 'blocklist grew'            # new blocks
```

Idle polls and health checks log at debug so the steady state is quiet.

## Behind a proxy

Set `APB_TRUST_PROXY=true` only when a proxy you control sets the forwarded
header. With it on and nothing in front, any client can forge its own address
and slip past the rate limits — which are per-address.

The service speaks plain HTTP and expects TLS to be terminated in front of it.
The supplied compose file wires up Traefik; anything else works the same way.
