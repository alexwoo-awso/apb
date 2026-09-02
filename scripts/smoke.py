"""Walk the console the way a person would: first-run setup, TOTP enrolment,
sign-in, device provisioning and a script download. Used as a manual smoke test
against a locally running apbd."""
import base64
import hmac
import hashlib
import http.cookiejar
import re
import struct
import sys
import time
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099"
CODE = sys.argv[2]

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def get(path):
    with opener.open(BASE + path) as r:
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()


def post(path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(req) as r:
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()


def csrf_of(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    if not m:
        raise SystemExit("no csrf token in page")
    return m.group(1)


def totp(secret_b32):
    key = base64.b32decode(secret_b32.replace(" ", "").upper() + "=" * (-len(secret_b32.replace(" ", "")) % 8))
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    val = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return "%06d" % (val % 1000000)


def check(label, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + label + ("  " + detail if detail and not cond else ""))
    if not cond:
        globals()["failures"] = globals().get("failures", 0) + 1


print("setup")
status, html, url = post("/setup", {
    "code": CODE, "username": "alex", "display_name": "Alex",
    "email": "alex@example.org",
    "password": "a reasonable passphrase here", "password2": "a reasonable passphrase here",
})
check("setup redirects to enrolment", url.endswith("/account/2fa"), url)

status, html, url = get("/account/2fa")
secret = re.search(r'class="mono selectable">([A-Z2-7 ]+)<', html).group(1)
check("enrolment page shows a secret", len(secret.replace(" ", "")) == 32, secret)

status, png, _ = get("/account/2fa/qr.png")
check("QR code renders", png[1:4] == "PNG", png[:8])

print("enrol")
status, html, url = post("/account/2fa", {"csrf": csrf_of(html), "code": totp(secret)})
check("enrolment completes", url.rstrip("/") == BASE, url)
check("dashboard renders", "blocked now" in html, html[:200])

print("console")
for path, needle in [
    ("/addresses", "Blocklist"),
    ("/whitelist", "Add a rule"),
    ("/devices", "Register a router"),
    ("/activity", "Replication log"),
    ("/audit", "entries"),
    ("/users", "Accounts"),
    ("/settings", "When an address gets blocked"),
    ("/account", "Change your password"),
    ("/help", "How a block travels"),
]:
    status, html, _ = get(path)
    check(path, status == 200 and needle in html, "status %d" % status)

print("provision a router")
status, html, _ = get("/devices")
token = csrf_of(html)
status, html, url = post("/devices", {
    "csrf": token, "name": "edge-1", "ros_branch": "v7",
    "sync_interval": "15", "report_interval": "300",
    "list_name": "APB", "detect_list": "APB_detect", "block_timeout": "520w",
})
check("device created", "/scripts" in url, url)

status, html, _ = get(url.replace(BASE, ""))
check("script preview renders", "apb-bootstrap" in html and "timeout=" in html)

dev_id = re.search(r"/devices/(\d+)/scripts", url).group(1)
status, rsc, _ = post("/devices/%s/scripts" % dev_id, {"csrf": csrf_of(html), "part": "install"})
check("install bundle downloads", "/system script add" in rsc, rsc[:120])
check("bundle carries a real token", "apb_" in rsc and "TOKENAPPEARSHERE" not in rsc)
check("every add has a timeout", rsc.count("address-list add") == rsc.count("timeout="),
      "%d adds, %d timeouts" % (rsc.count("address-list add"), rsc.count("timeout=")))
check("scheduler rebuilds after reboot", "start-time=startup" in rsc)

m = re.search(r'"(apb_[A-Za-z0-9]+)\\"', rsc) or re.search(r"apb_[A-Za-z0-9]{28}", rsc)
device_token = m.group(0).strip('"\\') if m else None
check("token extracted from bundle", bool(device_token), str(device_token))

print("router protocol")
req = urllib.request.Request(BASE + "/api/v1/report", data=b"45.83.64.7,91.240.118.3", method="POST")
req.add_header("Authorization", "Bearer " + device_token)
with urllib.request.urlopen(req) as r:
    out = r.read().decode()
check("report accepted", out.startswith("ok,"), out)

req = urllib.request.Request(BASE + "/api/v1/sync?c=0")
req.add_header("Authorization", "Bearer " + device_token)
with urllib.request.urlopen(req) as r:
    out = r.read().decode()
check("delta carries the new addresses", "+45.83.64.7" in out and "91.240.118.3" in out, out)
check("delta is one line", "\n" not in out, repr(out))

req = urllib.request.Request(BASE + "/api/v1/whoami")
req.add_header("Authorization", "Bearer " + device_token)
with urllib.request.urlopen(req) as r:
    out = r.read().decode()
check("whoami is a parseable csv line", out.startswith("1,edge-1,APB,"), out)

status, html, _ = get("/addresses")
check("blocklist shows the reported address", "45.83.64.7" in html)
status, html, _ = get("/")
check("dashboard counts the block", "blocked now" in html)

n = globals().get("failures", 0)
print("\n%s" % ("all checks passed" if n == 0 else "%d CHECK(S) FAILED" % n))
sys.exit(1 if n else 0)
