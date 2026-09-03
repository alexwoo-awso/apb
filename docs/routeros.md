# The RouterOS side

## What gets installed

Generate a bundle from **Devices → your router → Generate scripts**, upload it,
and import it:

```
/import file-name=apb-install.rsc
```

Then delete the file. It contains the router's token.

The bundle installs four scripts and three schedules, all prefixed `apb-`, and
runs the first rebuild immediately so you can see it work.

| Script | Schedule | What it does |
|---|---|---|
| `apb-sync` | `interval=15s`, `start-time=startup` | applies the delta since the cursor held in RAM |
| `apb-bootstrap` | `interval=0`, `start-time=startup` | rebuilds the whole list, in pages |
| `apb-report` | `interval=5m`, `start-time=startup` | uploads new entries from the detection list |
| `apb-purge` | manual | clears every address APB manages here |
| `apb-test` | manual | one call to the server, reporting exactly what came back |

Scripts run with `policy=read,write,test` — `test` is what `/tool fetch` needs.
The original APB scripts requested `ftp,reboot,policy,password,sniff,sensitive,
romon` as well; none of that is required.

## Nothing is written to flash

RouterOS stores an address-list entry in the configuration, on flash, **unless**
it has a timeout. Entries with a timeout are held in RAM and dropped on reboot.
Every entry APB adds carries `timeout=520w`.

That has three consequences worth knowing:

1. `/ip firewall address-list print` shows the entries but
   `/export` does not, because they are not configuration.
2. A reboot empties the list. This is intended, and `apb-bootstrap` refills it
   within seconds of the router coming up.
3. Memory, not flash, is the limit. Budget roughly 100–150 bytes per entry:
   50 000 addresses is a few megabytes, comfortable even on a hEX-class device.

`520w` is about ten years. It is chosen to sit below 536 870 911 seconds, above
which RouterOS displays a timeout as `0sec` even though it still tracks it
correctly — staying under keeps the list readable.

## How the router keeps its place

The replication cursor lives in a `:global` (`apbCursor`), which is RAM only.
The list and the cursor are therefore lost together on a reboot, which is
exactly what you want: if the cursor survived an empty list, the router would
believe it was up to date while protecting nothing.

`apb-sync` checks for the cursor first. No cursor means no list, so it hands
over to `apb-bootstrap`.

Two other globals guard against overlapping runs: `apbLock` and `apbBootLock`
hold the uptime at which a run started, and a lock older than a few minutes is
assumed dead and taken over. A fifteen-second schedule must never stack up.

## The shape of the generated file

Every line in a generated bundle is a complete command. The script bodies are
assembled into a variable one piece at a time and then installed, rather than
embedded as the single backslash-continued string RouterOS itself exports.

That matters because the export format is not safe to move between machines. A
continuation is a backslash followed by a newline, so a file that acquires CRLF
line endings on the way to the router — a download on Windows, an editor, a
copy-paste — puts a carriage return after the backslash, the line stops
continuing, the quoted string is left open, and `/import` fails with
`expected end of command` several lines later. RouterOS also strips leading
whitespace on a continuation line, so a break placed before a space silently
removes a space the script needed.

With no continuations neither can happen, and the file imports identically with
either line ending.

## Detection: what you have to provide

APB uploads whatever lands in the detection list (`APB_detect` by default). It
does not decide what is abusive — your firewall rules do. The generated
`apb-firewall-example.rsc` is a starting point, not a drop-in configuration:

- four staged rules that catch a fourth new SSH connection within three minutes
- a rule for unsolicited probes of the management ports
- a TCP port-scan detector
- two `drop` rules that enforce the shared list

**Read it before importing.** It appends to the end of your chains, and
firewall rules are evaluated in order, so the drop rules almost certainly need
moving above your accept rules or they will never be reached.

Anything that ends up in the detection list by any other means is contributed
too, so an existing detection setup can be pointed at that list instead.

## Reported-once bookkeeping

Entries created by `action=add-src-to-address-list` are dynamic and immutable,
so they cannot be marked as sent. `apb-report` instead keeps a second list —
`APB_detect_sent` — with a one-day timeout, and skips anything already in it.
Also RAM only, also gone after a reboot, at which point at most one day of
already-known addresses is re-sent and deduplicated server-side.

Each run uploads at most 300 addresses. Anything above that goes on the next
run five minutes later.

## Certificate verification

The token is a password, and it crosses the network on every call.

- **RouterOS 7** ships built-in trust anchors, so new devices default to
  `check-certificate=yes-without-crl` and verification just works.
- **RouterOS 6** has no trust store until you import a CA, so v6 devices default
  to `no` and the console flags it. To fix it properly, import the issuing root
  (for Let's Encrypt, ISRG Root X1):

  ```
  /tool fetch url="https://letsencrypt.org/certs/isrgrootx1.pem"
  /certificate import file-name=isrgrootx1.pem passphrase=""
  ```

  then switch the device to **Verify (no CRL)** in the console and regenerate
  its bundle.

CRL checking is off by default because a router that cannot reach the CRL
distribution point stops syncing, which trades a small risk for a large one.

## Troubleshooting

**`/import` fails with `expected end of command`.**

That is the signature of a bundle generated before this was fixed, or of a file
whose line continuations were broken in transit. Regenerate the bundle from the
console: current bundles contain no continuations and import the same with LF or
CRLF endings. Check with `/file print detail where name~"apb"` that the file
actually arrived whole.

**The router reaches the server but everything is 401.**

Check the server log. A rejection names the reason. `reason=user-agent` means
this instance has a required User-Agent set under Settings and the router is
sending a different one, which happens whenever that setting is changed without
regenerating the bundles built against the old value. The log line carries both
values. Either clear the setting or regenerate this router's bundle.
`reason="unknown token"` means the token was revoked, expired, or the device was
disabled.

**Nothing works and the log just repeats `rebuild failed`.**

Run the connectivity test. It is installed with the bundle and does exactly one
call, so it turns a retry loop into a single readable answer:

```
/system script run apb-test
/log print where message~"APB test"
```

It reports the transport it used, the fetch status, the server's raw reply and
whether the token was accepted. A healthy run logs a reply starting `1,`.

**Nothing appears in the console.**

```
/system scheduler print
/system script print
/log print where message~"APB"
```

The scripts log at info on success and warning or error on failure. If the log
is silent, the schedules are not running.

**Run a script by hand to see the error:**

```
/system script run apb-sync
/system script run apb-bootstrap
```

**Check the fetch itself.** A wrong token, a hostname that does not resolve or a
certificate the router will not accept all surface here:

```
/tool fetch url="https://apb.example.org/api/v1/whoami" \
  http-header-field="Authorization: Bearer apb_yourtoken" \
  check-certificate=yes-without-crl output=user as-value
```

A healthy answer is a comma-separated line starting `1,`. `401` means the token
is wrong or revoked. A TLS error means the certificate is not trusted — see
above.

**The list is empty after a reboot.** That is the design; it refills itself. If
it stays empty, `apb-bootstrap` is failing, so run it by hand and read the log.

**The console shows the router lagging.** Compare its cursor with the server's
on the device page. A large gap with a recent sync time means the router is
working through a backlog, which resolves itself. A large gap with an old sync
time means it is not reaching the server.

**Start over on a router:**

```
/system script run apb-purge     ← clears the lists and the cursor
/system script run apb-bootstrap ← rebuilds from the server
```

## Removing APB

Download `apb-uninstall.rsc` from the scripts page and import it. It runs the
purge, then removes the schedules and the scripts. Your own firewall rules are
left alone — the two `drop` rules referencing the list are yours to remove.

## RouterOS 6 versus 7

The generated scripts avoid anything version-specific: no `:while`, no
`:onerror`, no `:deserialize`. They use `:do { } on-error={ }`,
`:do { } while=( )` and `:toarray`, which behave the same on 6.49 and 7.x.
The differences are the certificate default above and the RouterOS 6 date
format, which the scripts never parse — the original APB did, and it was a
source of bugs around midnight.

Tested syntax targets 6.49.x and 7.x. The scripts have not been exercised on a
physical device by their author; validate on one router before rolling out
widely, and use `/system script run` with the log open to watch it work.
