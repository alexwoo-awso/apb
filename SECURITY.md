# Security policy

## Reporting a vulnerability

Open an issue at <https://github.com/alexwoo-awso/apb/issues>.

If the issue is sensitive, say so in a short issue without the detail and ask
for a private channel, rather than publishing a working exploit.

Please include: what you did, what happened, what you expected, and the version
from `apbd -version`. A minimal reproduction is worth more than a long report.

## Scope

In scope: authentication and session handling, the device token flow, the
RouterOS script generator, SQL and template injection, the content security
policy, and anything that lets one router affect another router's blocklist.

Out of scope, because they are documented design decisions rather than defects:

- A router token can read the whole blocklist. It is a list of addresses that
  attacked someone.
- RouterOS 6 defaults to unverified TLS, because it has no trust store until a
  CA is imported. The console flags it and `docs/routeros.md` explains the fix.
- An administrator with a working second factor can do anything. The audit log
  records it.

`docs/security.md` has the full threat model.

## Supported versions

The latest release. This is a small project; there is no backport branch.
