-- Shared rate limiting, for deployments with more than one node.
--
-- A single node keeps its buckets in memory; this table is what lets several
-- nodes enforce one limit instead of one each.

CREATE TABLE rate_limits (
    key        TEXT PRIMARY KEY,
    tokens     REAL NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_rate_limits_updated_at ON rate_limits (updated_at);
