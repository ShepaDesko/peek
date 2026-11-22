-- Files, multi-recipient bundles and secret requests.
--
-- Three ideas, one migration, because they share one notion: a *bundle*. A
-- bundle is what several recipient links have in common — the same encrypted
-- files, uploaded once. For a single-recipient secret the bundle is the secret
-- itself. Files belong to a bundle, never to one link, so ten recipients cost
-- one upload.

-- bundle_id groups the links that share files. It is the secret's own id when
-- there is one recipient, and the group id when there are several.
ALTER TABLE secrets ADD COLUMN bundle_id TEXT;

-- A deposit against a secret request: request_id says which request it answers,
-- wrapped_key is the content key sealed to the requester's public key (ECIES).
-- The server holds both and can read neither.
ALTER TABLE secrets ADD COLUMN request_id TEXT;
ALTER TABLE secrets ADD COLUMN wrapped_key BLOB;

CREATE INDEX idx_secrets_bundle ON secrets (bundle_id);
CREATE INDEX idx_secrets_request ON secrets (request_id);

-- One encrypted blob. The row holds no name, no MIME type and no key: those
-- live inside the sealed payload of each recipient's secret. Only the opaque
-- id (which is also the storage key) and the byte count are here.
CREATE TABLE secret_files (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    creator_id TEXT,
    -- NULL while the upload is still pending; set when a secret claims it.
    bundle_id  TEXT,
    -- SHA-256 of the upload token handed back at upload time. Attaching a blob
    -- to a secret requires it, so one uploader cannot claim another's blob.
    claim_token_hash BLOB NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    -- A pending upload expires quickly; an attached one follows its secret,
    -- and is pushed forward once more when a recipient reveals, so a download
    -- that started before the last view can still finish.
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_secret_files_bundle ON secret_files (bundle_id);
CREATE INDEX idx_secret_files_expires ON secret_files (expires_at);

-- A short-lived permission to download the blobs of one bundle, handed out by
-- a successful reveal. Without it the blobs are unreachable: proving possession
-- of the read token once is what opens them, and the secret row itself may
-- already be gone.
CREATE TABLE file_grants (
    token_hash BLOB PRIMARY KEY,
    org_id     TEXT NOT NULL,
    bundle_id  TEXT NOT NULL,
    secret_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_file_grants_expires ON file_grants (expires_at);
CREATE INDEX idx_file_grants_bundle ON file_grants (bundle_id);

-- "Send me the password for account X". The requester keeps the private key in
-- their own receipt link; the server stores only the public half, so a deposit
-- can be sealed to it and nobody else — not another depositor, not the server.
CREATE TABLE secret_requests (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    creator_id TEXT,
    -- Uncompressed SEC1 P-256 point, exactly as the browser exported it.
    public_key BLOB NOT NULL,
    -- Proof of possession for the deposit page, derived from the request key
    -- in the deposit link's fragment, exactly like a secret's read token.
    read_token_hash    BLOB NOT NULL,
    receipt_token_hash BLOB NOT NULL,
    -- The prompt the depositor reads, sealed with the request key.
    prompt_enc      BLOB,
    kdf_salt        BLOB NOT NULL,
    kdf_memory_kib  INTEGER NOT NULL,
    kdf_iterations  INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    label_enc        BLOB,
    notify_email_enc BLOB,
    notify_on_deposit INTEGER NOT NULL DEFAULT 0,
    max_deposits     INTEGER NOT NULL DEFAULT 1,
    deposits_used    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_secret_requests_expires ON secret_requests (expires_at);
CREATE INDEX idx_secret_requests_creator ON secret_requests (creator_id);
