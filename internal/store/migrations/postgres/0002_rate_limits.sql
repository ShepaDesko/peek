-- Shared rate limiting, for deployments with more than one node.

CREATE TABLE rate_limits (
    key        TEXT PRIMARY KEY,
    tokens     DOUBLE PRECISION NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_rate_limits_updated_at ON rate_limits (updated_at);
