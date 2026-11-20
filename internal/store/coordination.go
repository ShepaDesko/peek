package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Coordination primitives for multi-node deployments.
//
// Peek has no Redis and no external scheduler. When several nodes share a
// PostgreSQL database, the lock below decides which one runs a periodic job,
// and the token bucket below gives them one shared rate limit instead of one
// each.

// TryLock claims a named lock until now+ttl and reports whether it was taken.
//
// It is safe on a single node too, where it simply always succeeds. An expired
// lock is stolen on purpose: a node that died mid-job must not block the
// others forever.
func (s *Store) TryLock(ctx context.Context, name, holder string, ttl time.Duration, now time.Time) (bool, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	expires := unix(now.Add(ttl))

	res, err := s.exec(ctx, `INSERT INTO job_locks (name, holder, acquired_at, expires_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET holder = ?, acquired_at = ?, expires_at = ?
		WHERE job_locks.expires_at <= ? OR job_locks.holder = ?`,
		name, holder, unix(now), expires,
		holder, unix(now), expires,
		unix(now), holder)
	if err != nil {
		return false, fmt.Errorf("store: claim lock %q: %w", name, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		// Some drivers do not report it; fall back to reading the row back.
		return s.holdsLock(ctx, name, holder, now)
	}
	return affected > 0, nil
}

func (s *Store) holdsLock(ctx context.Context, name, holder string, now time.Time) (bool, error) {
	var (
		current string
		expires int64
	)
	err := s.queryRow(ctx, `SELECT holder, expires_at FROM job_locks WHERE name = ?`, name).Scan(&current, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return current == holder && expires > unix(now), nil
}

// Unlock releases a lock held by holder. Releasing someone else's lock is a
// no-op rather than an error.
func (s *Store) Unlock(ctx context.Context, name, holder string) error {
	_, err := s.exec(ctx, `DELETE FROM job_locks WHERE name = ? AND holder = ?`, name, holder)
	return err
}

// RateAllow consumes one token from a bucket shared by every node.
//
// Same shape as the in-memory limiter: burst tokens immediately, then refill
// at rate per second.
//
// It is deliberately a single statement. Reading the row and writing it back,
// even inside a transaction with SELECT … FOR UPDATE, lets the very first
// burst through once per node: there is no row yet, so there is nothing to
// lock, and every caller inserts the same fresh bucket. Forty callers got
// through a burst of five that way, on PostgreSQL, in the test below.
//
// Here the refill, the spend and the limit all happen inside one upsert: the
// WHERE on the conflict branch is what refuses the request, and RETURNING is
// what tells us it did.
func (s *Store) RateAllow(ctx context.Context, key string, burst float64, refillPerSecond float64, now time.Time) (bool, error) {
	if burst <= 0 {
		return true, nil
	}
	// SQLite spells the two-argument minimum MIN; PostgreSQL spells it LEAST.
	minFn := "MIN"
	if s.driver == "postgres" {
		minFn = "LEAST"
	}
	refilled := fmt.Sprintf("%s(?, rate_limits.tokens + (? - rate_limits.updated_at) * ?)", minFn)

	query := fmt.Sprintf(`INSERT INTO rate_limits (key, tokens, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE
		   SET tokens = %s - 1, updated_at = ?
		 WHERE %s >= 1
		RETURNING tokens`, refilled, refilled)

	ts := unix(now)
	var tokens float64
	err := s.queryRow(ctx, query,
		key, burst-1, ts, // the bucket this caller creates, already spending one token
		burst, ts, refillPerSecond, ts, // the update branch
		burst, ts, refillPerSecond, // its guard
	).Scan(&tokens)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		// The guard refused the update: the bucket is empty.
		return false, nil
	default:
		// A limiter that cannot reach its state must not take the service
		// down: fail open, and let the caller log it.
		return true, fmt.Errorf("store: rate limit %q: %w", key, err)
	}
}

// PurgeRateLimits drops buckets nobody has touched for a while, so a flood of
// distinct addresses cannot grow the table without bound.
func (s *Store) PurgeRateLimits(ctx context.Context, idle time.Duration, now time.Time) (int64, error) {
	if idle <= 0 {
		idle = time.Hour
	}
	res, err := s.exec(ctx, `DELETE FROM rate_limits WHERE updated_at < ?`, unix(now.Add(-idle)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
