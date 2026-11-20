package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// RateLimiter is what the middleware needs: a verdict per client, and a hint
// for Retry-After.
type RateLimiter interface {
	Allow(key string) bool
	RetryAfter() int
}

// sharedLimiter enforces one limit across every node through the database.
//
// A single node keeps its buckets in memory, which costs nothing. As soon as
// several nodes share a PostgreSQL database, in-memory buckets would give each
// node its own allowance — a three-node cluster would let three times the
// configured burst through — so the bucket moves into the database.
type sharedLimiter struct {
	store  *store.Store
	log    *slog.Logger
	class  string
	burst  float64
	refill float64 // tokens per second
	window time.Duration
}

func newSharedLimiter(st *store.Store, log *slog.Logger, class string, rl config.RateLimit) *sharedLimiter {
	window := rl.Window.Std()
	if window <= 0 {
		window = time.Hour
	}
	refill := 0.0
	if rl.Rate > 0 {
		refill = float64(rl.Rate) / window.Seconds()
	}
	return &sharedLimiter{
		store:  st,
		log:    log,
		class:  class,
		burst:  float64(rl.Burst),
		refill: refill,
		window: window,
	}
}

func (l *sharedLimiter) Allow(key string) bool {
	if l == nil || l.burst <= 0 || key == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, err := l.store.RateAllow(ctx, l.class+":"+key, l.burst, l.refill, time.Now())
	if err != nil {
		// RateAllow fails open; record why, because a limiter that is silently
		// off is worse than one that is noisily degraded.
		l.log.Error("shared rate limiter unavailable, allowing the request",
			"class", l.class, "error", err.Error())
	}
	return ok
}

func (l *sharedLimiter) RetryAfter() int {
	if l == nil || l.refill <= 0 {
		return 60
	}
	seconds := int(1/l.refill) + 1
	switch {
	case seconds < 1:
		return 1
	case seconds > 3600:
		return 3600
	default:
		return seconds
	}
}

// newLimiter picks the right implementation for the deployment.
func newLimiter(st *store.Store, log *slog.Logger, cfg *config.Config, class string, rl config.RateLimit) RateLimiter {
	if st != nil && st.Driver() == "postgres" {
		return newSharedLimiter(st, log, class, rl)
	}
	_ = cfg
	return NewLimiter(rl)
}
