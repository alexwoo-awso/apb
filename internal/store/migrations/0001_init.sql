-- APB2 initial schema.
-- All timestamps are unix seconds (INTEGER). All IPs are stored both as
-- canonical text and as a fixed 16-byte blob (IPv4 held as IPv4-mapped) so
-- that CIDR containment can be answered with a plain BETWEEN range scan.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE admins (
    id                   INTEGER PRIMARY KEY,
    username             TEXT NOT NULL COLLATE NOCASE,
    display_name         TEXT NOT NULL DEFAULT '',
    email                TEXT NOT NULL DEFAULT '',
    pass_hash            TEXT NOT NULL,
    role                 TEXT NOT NULL DEFAULT 'admin',   -- owner | admin | viewer
    totp_secret          BLOB,                            -- sealed with the server key
    totp_enrolled        INTEGER NOT NULL DEFAULT 0,
    disabled             INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    created_by           TEXT NOT NULL DEFAULT '',
    last_login_at        INTEGER NOT NULL DEFAULT 0,
    last_login_ip        TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE UNIQUE INDEX admins_username ON admins(username);

-- Session ids are never stored verbatim: the cookie carries a random 32-byte
-- value, the table holds its SHA-256.
CREATE TABLE sessions (
    id           BLOB PRIMARY KEY,
    admin_id     INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf         TEXT NOT NULL,
    pending_totp INTEGER NOT NULL DEFAULT 0,   -- 1 = password ok, 2FA outstanding
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX sessions_admin ON sessions(admin_id);
CREATE INDEX sessions_expires ON sessions(expires_at);

CREATE TABLE devices (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL COLLATE NOCASE,
    identity        TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    ros_branch      TEXT NOT NULL DEFAULT 'v7',            -- v6 | v7
    ros_version     TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,

    -- client configuration, delivered to the router by /api/v1/whoami
    list_name       TEXT NOT NULL DEFAULT 'APB',
    detect_list     TEXT NOT NULL DEFAULT 'APB_detect',
    block_timeout   TEXT NOT NULL DEFAULT '520w',
    verify_cert     TEXT NOT NULL DEFAULT 'yes-without-crl',  -- yes | yes-without-crl | no
    sync_interval   INTEGER NOT NULL DEFAULT 15,           -- seconds
    report_interval INTEGER NOT NULL DEFAULT 300,          -- seconds
    contribute      INTEGER NOT NULL DEFAULT 1,            -- may submit reports
    consume         INTEGER NOT NULL DEFAULT 1,            -- receives the blocklist
    ipv6            INTEGER NOT NULL DEFAULT 0,

    -- observed state
    cursor          INTEGER NOT NULL DEFAULT 0,
    applied         INTEGER NOT NULL DEFAULT 0,
    last_sync_at    INTEGER NOT NULL DEFAULT 0,
    last_report_at  INTEGER NOT NULL DEFAULT 0,
    last_boot_at    INTEGER NOT NULL DEFAULT 0,
    last_ip         TEXT NOT NULL DEFAULT '',
    reports_total   INTEGER NOT NULL DEFAULT 0,

    tags            TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE UNIQUE INDEX devices_name ON devices(name);

CREATE TABLE device_tokens (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    label        TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL,          -- leading chars, shown in the UI
    hash         BLOB NOT NULL,          -- HMAC-SHA256(server key, token)
    created_at   INTEGER NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   INTEGER NOT NULL DEFAULT 0,
    revoked_at   INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    use_count    INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE UNIQUE INDEX device_tokens_hash ON device_tokens(hash);
CREATE INDEX device_tokens_device ON device_tokens(device_id);

CREATE TABLE addresses (
    id             INTEGER PRIMARY KEY,
    ip             TEXT NOT NULL,
    ip_bin         BLOB NOT NULL,        -- always 16 bytes
    family         INTEGER NOT NULL,     -- 4 | 6
    state          TEXT NOT NULL DEFAULT 'blocked',  -- blocked | released
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    report_count   INTEGER NOT NULL DEFAULT 0,
    device_count   INTEGER NOT NULL DEFAULT 0,
    expires_at     INTEGER NOT NULL DEFAULT 0,       -- 0 = no expiry
    country        TEXT NOT NULL DEFAULT '',
    country_name   TEXT NOT NULL DEFAULT '',
    continent      TEXT NOT NULL DEFAULT '',
    asn            INTEGER NOT NULL DEFAULT 0,
    asn_org        TEXT NOT NULL DEFAULT '',
    geo_at         INTEGER NOT NULL DEFAULT 0,
    source         TEXT NOT NULL DEFAULT 'report',   -- report | manual | import
    notes          TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL DEFAULT '',
    blocked_at     INTEGER NOT NULL DEFAULT 0,
    released_at    INTEGER NOT NULL DEFAULT 0,
    release_reason TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE UNIQUE INDEX addresses_ip ON addresses(ip);
CREATE INDEX addresses_bin ON addresses(ip_bin);
CREATE INDEX addresses_state_seen ON addresses(state, last_seen DESC);
CREATE INDEX addresses_state_reports ON addresses(state, report_count DESC);
CREATE INDEX addresses_state_devices ON addresses(state, device_count DESC);
CREATE INDEX addresses_country ON addresses(country);
CREATE INDEX addresses_asn ON addresses(asn);
CREATE INDEX addresses_first_seen ON addresses(first_seen DESC);
CREATE INDEX addresses_expires ON addresses(expires_at) WHERE expires_at > 0;
CREATE INDEX addresses_geo_at ON addresses(geo_at);

-- One row per (address, device): who saw it, when they first and last saw it.
CREATE TABLE reports (
    address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    first_at   INTEGER NOT NULL,
    last_at    INTEGER NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (address_id, device_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX reports_device ON reports(device_id, last_at DESC);

-- Raw stream for the activity view; pruned by the retention job.
CREATE TABLE report_events (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    device_id  INTEGER NOT NULL,
    address_id INTEGER NOT NULL,
    ip         TEXT NOT NULL,
    fresh      INTEGER NOT NULL DEFAULT 0   -- 1 = address was previously unknown
) STRICT;
CREATE INDEX report_events_at ON report_events(at DESC);
CREATE INDEX report_events_device ON report_events(device_id, at DESC);

CREATE TABLE whitelist (
    id         INTEGER PRIMARY KEY,
    cidr       TEXT NOT NULL,
    net_start  BLOB NOT NULL,            -- 16 bytes, inclusive
    net_end    BLOB NOT NULL,            -- 16 bytes, inclusive
    prefix_len INTEGER NOT NULL,
    family     INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    hits       INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE UNIQUE INDEX whitelist_cidr ON whitelist(cidr);
CREATE INDEX whitelist_start ON whitelist(net_start);
CREATE INDEX whitelist_expires ON whitelist(expires_at) WHERE expires_at > 0;

-- The replication log. Every router tracks a cursor into this table; the
-- sequence is monotonic and never reused (AUTOINCREMENT).
CREATE TABLE changes (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    op     TEXT NOT NULL,        -- A = add to blocklist, R = remove
    ip     TEXT NOT NULL,
    family INTEGER NOT NULL,
    at     INTEGER NOT NULL
) STRICT;
CREATE INDEX changes_at ON changes(at);

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT 'system',   -- admin | device | system
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    ok         INTEGER NOT NULL DEFAULT 1
) STRICT;
CREATE INDEX audit_log_at ON audit_log(at DESC);
CREATE INDEX audit_log_actor ON audit_log(actor, at DESC);

CREATE TABLE ui_hints (
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    hint     TEXT NOT NULL,
    seen_at  INTEGER NOT NULL,
    PRIMARY KEY (admin_id, hint)
) STRICT, WITHOUT ROWID;

CREATE TABLE metrics_hourly (
    hour       INTEGER NOT NULL,     -- unix seconds truncated to the hour
    device_id  INTEGER NOT NULL DEFAULT 0,   -- 0 = all devices
    reports    INTEGER NOT NULL DEFAULT 0,
    additions  INTEGER NOT NULL DEFAULT 0,
    removals   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, device_id)
) STRICT, WITHOUT ROWID;
