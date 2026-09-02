# Reference RouterOS bundles

These files are **examples, not something to import**. They are what the
generator produces for a device called `edge-1` pointing at
`https://apb.example.org`, with the token replaced by the placeholder
`apb_SAMPLETOKENONLY000000`.

They are committed so the scripts can be read and reviewed without running the
service — in a pull request, in an audit, or before you decide to deploy
anything at all.

Get the real bundle for a real router from the console:

> Devices → *your router* → Generate scripts → `apb-install.rsc`

It embeds that router's own freshly issued token and its own settings.
Regenerate them with:

```sh
make sample
```

## What is here

| File | Contents |
|---|---|
| `v7/apb-install.rsc` | the whole bundle for RouterOS 7: four scripts, three schedules, and a first rebuild |
| `v7/apb-scripts.rsc` | the script definitions alone |
| `v7/apb-scheduler.rsc` | the schedules alone |
| `v7/apb-install-ipv6.rsc` | the same, for a device with IPv6 handling enabled |
| `v7/apb-uninstall.rsc` | removes everything the bundle installs |
| `v7/apb-firewall-example.rsc` | example detection and enforcement rules |
| `v6/…` | the same for RouterOS 6.49.x, which defaults to unverified TLS because it has no trust store until a CA is imported |

## Reading them

The scripts are stored the way RouterOS exports them: one long quoted string per
script, with `\r\n` for newlines and a trailing backslash wrapping long lines.
That is unpleasant to read directly. To recover the plain script:

```sh
sed 's/\\$//' apb-install.rsc | tr -d '\n' | \
  sed 's/\\r\\n/\n/g; s/\\"/"/g; s/\\\$/$/g; s/\\?/?/g'
```

Or run `make sample` and read `bin/sample/`, where the same content is produced
without the escaping applied twice.

## The important bit

Every `address-list add` in these scripts carries `timeout=520w`. That is what
keeps entries in RAM instead of on the router's flash, and it is the whole
reason this rework exists. If you edit these scripts by hand, do not remove it.

See [../../docs/routeros.md](../../docs/routeros.md) for what each script does,
how detection works, and how to troubleshoot a router that is not syncing.
