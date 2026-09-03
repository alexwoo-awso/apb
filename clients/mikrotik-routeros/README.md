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

## How the file is put together

Each script body is assembled one piece at a time into a variable and then
installed:

```
:set apbSrc ""
:set apbSrc ($apbSrc . ":local Url \"https://apb.example.org/api/v1\"\r\n")
:set apbSrc ($apbSrc . ":local Token \"apb_...\"\r\n")
/system script add name="apb-sync" policy=read,write,test source=$apbSrc
```

That is more verbose than the single wrapped string RouterOS exports, and it is
deliberate. The export format ends long lines with a backslash to continue them,
which fails in two ways this generator cannot control:

* RouterOS strips leading whitespace on a continuation line, so a break placed
  before a space silently eats a space that belonged to the script;
* the continuation is a backslash followed by a newline, so a file that picks up
  CRLF line endings anywhere in transit — a download on Windows, an editor, a
  copy-paste — puts a carriage return after the backslash and the line stops
  continuing. The string is left open and `/import` fails with
  `expected end of command` some lines later.

With no continuations, every line is a complete command, and the file imports
the same whether it has LF or CRLF endings.

To read the script a bundle installs, either import it and run
`/system script print` on the router, or run `make sample` and read
`bin/sample/`, which writes the same content unescaped.

## The important bit

Every `address-list add` in these scripts carries `timeout=520w`. That is what
keeps entries in RAM instead of on the router's flash, and it is the whole
reason this rework exists. If you edit these scripts by hand, do not remove it.

See [../../docs/routeros.md](../../docs/routeros.md) for what each script does,
how detection works, and how to troubleshoot a router that is not syncing.
