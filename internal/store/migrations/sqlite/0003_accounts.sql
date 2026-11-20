-- Accounts, sessions and the second factors (milestone M5).
--
-- Nothing here stores a password, a TOTP seed or a session token in a form
-- that is useful to whoever steals the file: passwords are Argon2id hashes,
-- TOTP seeds are encrypted with the server master key, and a session row is
-- keyed by the SHA-256 of the cookie value rather than the value itself.

CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT NOT NULL REFERENCES organizations (id),
    email                TEXT NOT NULL,
    -- Lowercased and trimmed, for lookups and uniqueness.
    email_key            TEXT NOT NULL,
    password_hash        TEXT,
    display_name         TEXT NOT NULL DEFAULT '',
    role                 TEXT NOT NULL DEFAULT 'member',
    status               TEXT NOT NULL DEFAULT 'active',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    totp_secret_enc      BLOB,
    totp_confirmed_at    INTEGER,
    failed_logins        INTEGER NOT NULL DEFAULT 0,
    locked_until         INTEGER,
    last_login_at        INTEGER,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE UNIQUE INDEX idx_users_email ON users (org_id, email_key);
CREATE INDEX idx_users_status ON users (org_id, status);

-- One-time codes for when the authenticator is lost.
CREATE TABLE recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE INDEX idx_recovery_user ON recovery_codes (user_id);

-- A session row is identified by SHA-256(cookie value): the cookie itself is
-- never stored, so a database dump cannot be replayed as a login.
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id       TEXT NOT NULL,
    csrf_hash    BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    -- A session that has passed the password but not yet the second factor.
    mfa_pending  INTEGER NOT NULL DEFAULT 0,
    revoked_at   INTEGER
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

CREATE TABLE passkeys (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL,
    public_key    BLOB NOT NULL,
    attestation   TEXT,
    aaguid        BLOB,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,
    name          TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backed_up     INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);

CREATE UNIQUE INDEX idx_passkeys_credential ON passkeys (credential_id);
CREATE INDEX idx_passkeys_user ON passkeys (user_id);

-- Short-lived WebAuthn challenges. A challenge must be used once and quickly.
CREATE TABLE webauthn_challenges (
    id         TEXT PRIMARY KEY,
    user_id    TEXT,
    kind       TEXT NOT NULL,
    data       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_webauthn_expires ON webauthn_challenges (expires_at);

CREATE TABLE invitations (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES organizations (id),
    email           TEXT NOT NULL,
    email_key       TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'member',
    token_hash      BLOB NOT NULL,
    invited_by      TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    accepted_at     INTEGER,
    accepted_user_id TEXT
);

CREATE INDEX idx_invitations_org ON invitations (org_id, email_key);
CREATE INDEX idx_invitations_expires ON invitations (expires_at);

CREATE TABLE password_resets (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE INDEX idx_password_resets_user ON password_resets (user_id);
