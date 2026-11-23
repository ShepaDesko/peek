-- The webhook delivery queue.
--
-- A webhook is an outbound call, which means it can be slow, refused or
-- unreachable, and none of that may slow a reveal down or lose the event. So
-- nothing is sent from the request path: the event is written here, and a
-- background job delivers it.
--
-- The queue lives in the database rather than in memory for two reasons. A
-- restart in the middle of a retry window would otherwise drop the event, and
-- a cluster of nodes behind a load balancer would each deliver its own copy.
-- With the rows here, the job lock decides which node drains the queue.
CREATE TABLE webhook_deliveries (
    id     TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    -- The configured endpoint name, not its URL: an operator who changes the
    -- URL keeps the queue, and the row never grows a copy of a credential
    -- that may be embedded in it.
    endpoint TEXT NOT NULL,
    event    TEXT NOT NULL,
    -- The exact bytes that get signed and sent. Frozen at enqueue time so a
    -- retry delivers what the first attempt promised, byte for byte, and the
    -- signature a receiver checks is the signature over what it received.
    payload TEXT NOT NULL,

    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    -- Exactly one of these is set once the row is finished with: it either
    -- arrived or it ran out of attempts. Both NULL means still in the queue.
    delivered_at INTEGER,
    failed_at    INTEGER,
    -- What the last attempt saw. Kept for the operator, who otherwise has to
    -- correlate journald on whichever node happened to hold the lock.
    last_status INTEGER,
    last_error  TEXT
);

-- The draining query: the oldest unfinished row whose turn has come.
CREATE INDEX idx_webhook_pending ON webhook_deliveries (next_attempt_at)
WHERE delivered_at IS NULL AND failed_at IS NULL;

CREATE INDEX idx_webhook_created ON webhook_deliveries (created_at);
