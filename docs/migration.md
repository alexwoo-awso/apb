# Migrating from the original APB

## What changes

| | Original | Now |
|---|---|---|
| Storage | CSV files merged by a cron script | SQLite with an append-only change log |
| Router auth | one HTTP Basic password in every script | a token per router, revocable individually |
| Push | hourly | every 5 minutes |
| Pull | hourly | every 15 seconds |
| Address-list entries | no timeout, written to **flash** | `timeout=520w`, held in **RAM** |
| Removals | `rem.csv` existed but was never generated | a first-class operation that reaches every router |
| After a reboot | list survived on flash | list rebuilt from the server in seconds |
| Attribution | none | which router saw what, and when |
| Administration | edit files on the host | a web console |

The two that matter operationally: **entries no longer touch flash**, and
**removals work**.

## The plan

The old and new systems can run side by side. Nothing forces a flag day.

### 1. Stand up the new service

Give it its own hostname, or a path on the same one. Follow the quick start in
the [README](../README.md): bring up the stack, read the setup code from the
log, create an administrator, enrol an authenticator.

### 2. Whitelist your own networks first

Before importing anything. Old lists accumulate mistakes, and the whitelist is
what stops one from reaching every router at once.

**Whitelist → Add a rule**, or:

```sh
docker compose exec apb /apbctl whitelist add --cidr 198.51.100.0/24 \
  --reason "office uplink"
```

### 3. Import the existing list

Create a device row to attribute the history to, then import:

```sh
docker compose exec apb /apbctl admin list        # confirm you can reach it
docker compose exec apb /apbctl device list

# From the console: Devices → Register a router → name it "legacy-import"

docker compose cp ./src/r/snapshots/add.csv apb:/tmp/add.csv
docker compose exec apb /apbctl import-legacy --device legacy-import --file /tmp/add.csv
```

`--file` also takes a directory, which is how the pending uploads in the old
`src/w/` are drained:

```sh
docker compose cp ./src/w apb:/tmp/w
docker compose exec apb /apbctl import-legacy --device legacy-import --file /tmp/w
```

Imported addresses go through exactly the same validation as a live report:
private, reserved and documentation ranges are dropped, anything covered by a
whitelist rule is skipped, and duplicates collapse. The summary says how many of
each.

### 4. Move routers over, one at a time

For each router: register it in the console, generate `apb-install.rsc`, import
it, and watch the device page turn online. Then remove the old scripts:

```
/system scheduler remove [find name~"^sch_apb"]
/system script remove [find name~"^apb(GET|POST)$"]
```

The old permanent entries are still on flash. Clear them once the new list has
built — check the count on the device page first, and substitute whatever list
name your old scripts used:

```
/ip firewall address-list remove [find list=YOUR_OLD_LIST_NAME]
```

Point your firewall rules at the new list name (`APB` by default), or set the
device's list name to the old one so the rules keep working unchanged.

### 5. Keeping the stragglers reporting

If some routers cannot be converted immediately, the compatibility endpoints
keep them contributing. In `.env`:

```sh
APB_LEGACY_UPLOAD=true
APB_LEGACY_DEVICE=legacy-routers            # a device that must already exist
APB_LEGACY_AUTH=Basic dXNlcjpwYXNzd29yZA==  # exactly what the old scripts send
APB_LEGACY_USER_AGENT=your-old-agent        # the old nginx User-Agent gate
```

This serves `POST /up.php` and the `GET /r/...` snapshot paths at their original
addresses. Be clear about what it is:

- Every legacy router shares one credential, and everything they upload is
  attributed to one device row. Corroboration counting cannot distinguish them.
- `add.csv` is the whole list every time — the old client has no cursor.
- **`rem.csv` stays empty.** The old format cannot express a removal. Legacy
  routers will never unblock anything, which is the original bug and the reason
  to finish the migration.

Turn it off once the last router is converted.

### 6. Retire the old stack

```sh
cd /opt/docker/apb
docker compose down
crontab -e                 # remove the process_incoming.sh entry
```

Keep `src/r/snapshots/` and `web_opt/.htpasswd` somewhere safe until you are
sure, then destroy them — that htpasswd hash was the credential for every
router you ever deployed.

## Rotating what the old system leaked

The original design put one Basic credential into every router script, in an
`.rsc` file that was often kept around, and the same string appears in every
export. Treat it as public:

- Change the htpasswd password, or just delete the file with the old stack.
- If that password was reused anywhere else, change it there too.
- New tokens are per-router, shown once, and revocable individually — but only
  if you generate a fresh bundle per router rather than reusing one.

## Rolling back

The old stack is untouched by any of this: it has its own compose file, its own
volumes and its own cron entry. If the new service does not work out, bring the
old one back up and re-import the old scripts on the routers. Nothing in the
migration modifies the original files.
