-- Scoped API tokens, PostgreSQL dialect.
-- Mirrors migrations/sqlite/0007_api_tokens.sql.
--
-- A token belongs to a user and can never exceed that user's role: it is a
-- narrower key to the same door, not a second door. What it adds on top is a
-- scope list, so a script that only creates secrets cannot read the audit
-- trail even if its owner could.
--
-- The secret half is stored as SHA-256 and nothing else, like every other
-- token in Peek. The id half is in the clear because it is the lookup key —
-- which is also what lets a leaked token be revoked by name without a
-- database scan.
CREATE TABLE api_tokens (
    id      TEXT PRIMARY KEY,
    org_id  TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id),
    -- What the operator calls it. Shown in listings and in the audit trail, so
    -- a leak can be traced to the script that leaked it.
    name        TEXT NOT NULL,
    secret_hash BYTEA NOT NULL,
    -- Space-separated scope list. A text column rather than a join table: the
    -- set is small, fixed by the code, and always read whole.
    scopes     TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    -- 0 means no expiry. The interface pushes a date; the CLI allows neither
    -- by accident.
    expires_at   BIGINT NOT NULL DEFAULT 0,
    last_used_at BIGINT,
    -- Revocation is a timestamp, not a deletion: an audit trail that mentions
    -- a token must still be able to name it.
    revoked_at BIGINT
);

CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);
CREATE INDEX idx_api_tokens_expires ON api_tokens (expires_at);
