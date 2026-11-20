-- Peek initial schema.
--
-- Two rules shape every table here:
--   1. no secret content, label or passphrase is ever stored in the clear;
--   2. a secret row disappears the moment it is consumed, expired or burned,
--      and only the tombstone plus the append-only audit trail remain.

CREATE TABLE organizations (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    policies   TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);

CREATE TABLE secrets (
    id                     TEXT PRIMARY KEY,
    org_id                 TEXT NOT NULL REFERENCES organizations (id),
    creator_id             TEXT,
    kind                   TEXT NOT NULL,
    -- Sealed payload. Small secrets live inline; files are referenced in
    -- storage_ref and kept out of the database.
    ciphertext             BLOB,
    storage_ref            TEXT,
    size_bytes             INTEGER NOT NULL DEFAULT 0,
    -- SHA-256 of the read token. The token itself is derived in the browser
    -- from the key in the URL fragment and never stored.
    read_token_hash        BLOB NOT NULL,
    -- SHA-256 of the sender receipt token, which authorises status and burn.
    receipt_token_hash     BLOB NOT NULL,
    kdf_salt               BLOB NOT NULL,
    kdf_memory_kib         INTEGER NOT NULL,
    kdf_iterations         INTEGER NOT NULL,
    kdf_parallelism        INTEGER NOT NULL,
    has_passphrase         INTEGER NOT NULL DEFAULT 0,
    retrieval_step         INTEGER NOT NULL DEFAULT 1,
    deletable_by_recipient INTEGER NOT NULL DEFAULT 0,
    views_max              INTEGER NOT NULL,
    views_remaining        INTEGER NOT NULL,
    failed_attempts        INTEGER NOT NULL DEFAULT 0,
    max_failed_attempts    INTEGER NOT NULL,
    -- Sender-only metadata, encrypted client side like everything else.
    label_enc              BLOB,
    group_id               TEXT,
    created_at             INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    last_viewed_at         INTEGER
);

CREATE INDEX idx_secrets_expires_at ON secrets (expires_at);
CREATE INDEX idx_secrets_group_id ON secrets (group_id);
CREATE INDEX idx_secrets_creator ON secrets (creator_id);

-- What is left of a secret once it is gone: enough for the sender receipt page
-- to say what happened, and nothing more.
CREATE TABLE secret_tombstones (
    id                 TEXT PRIMARY KEY,
    org_id             TEXT NOT NULL,
    creator_id         TEXT,
    receipt_token_hash BLOB NOT NULL,
    status             TEXT NOT NULL,
    views_used         INTEGER NOT NULL DEFAULT 0,
    views_max          INTEGER NOT NULL DEFAULT 0,
    group_id           TEXT,
    created_at         INTEGER NOT NULL,
    closed_at          INTEGER NOT NULL
);

CREATE INDEX idx_tombstones_closed_at ON secret_tombstones (closed_at);

-- Append-only. Never updated, never deleted except by the retention job.
CREATE TABLE audit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL,
    secret_id  TEXT,
    user_id    TEXT,
    event      TEXT NOT NULL,
    at         INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    detail     TEXT
);

CREATE INDEX idx_audit_secret ON audit_events (secret_id, at);
CREATE INDEX idx_audit_at ON audit_events (at);
CREATE INDEX idx_audit_event ON audit_events (event, at);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Cooperative lock so that exactly one node runs a periodic job in HA.
CREATE TABLE job_locks (
    name        TEXT PRIMARY KEY,
    holder      TEXT NOT NULL,
    acquired_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

INSERT INTO organizations (id, slug, name, policies, created_at)
VALUES ('default', 'default', 'Default', '{}', 0);
