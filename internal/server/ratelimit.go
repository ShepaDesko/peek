package server

import (
	"sync"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// Limiter is a per-client-IP token bucket.
//
// In-memory is the right shape for a single node, which is the default
// deployment. A multi-node instance needs one bucket for the whole cluster
// instead, and gets it from sharedLimiter in limiter.go — newLimiter picks
// between the two on the driver, because sharing costs a round trip per
// request and a single node has nothing to share with.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	burst    float64
	refill   float64 // tokens per second
	window   time.Duration
	now      func() time.Time
	lastGC   time.Time
	disabled bool
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// NewLimiter builds a limiter from a configured rate limit. A non-positive
// burst disables limiting entirely, which is sometimes what an internal-only
// instance wants.
func NewLimiter(rl config.RateLimit) *Limiter {
	l := &Limiter{
		buckets: map[string]*bucket{},
		burst:   float64(rl.Burst),
		window:  rl.Window.Std(),
		now:     time.Now,
	}
	if rl.Burst <= 0 {
		l.disabled = true
		return l
	}
	if l.window <= 0 {
		l.window = time.Hour
	}
	if rl.Rate > 0 {
		l.refill = float64(rl.Rate) / l.window.Seconds()
	}
	l.lastGC = l.now()
	return l
}

// Allow consumes one token for key and reports whether the request may proceed.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.disabled || key == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.gcLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, seen: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.seen).Seconds()
	if elapsed > 0 {
		b.tokens = minFloat(l.burst, b.tokens+elapsed*l.refill)
	}
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfter returns a hint, in seconds, for the Retry-After header.
func (l *Limiter) RetryAfter() int {
	if l == nil || l.refill <= 0 {
		return 60
	}
	seconds := int(1/l.refill) + 1
	if seconds < 1 {
		return 1
	}
	if seconds > 3600 {
		return 3600
	}
	return seconds
}

// gcLocked drops buckets that have been full and idle for a while, so a flood
// of distinct source addresses cannot grow the map without bound.
func (l *Limiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	idle := l.window
	if idle < 5*time.Minute {
		idle = 5 * time.Minute
	}
	for key, b := range l.buckets {
		if now.Sub(b.seen) > idle {
			delete(l.buckets, key)
		}
	}
}

// Size reports the number of tracked clients. Exposed for tests and doctor.
func (l *Limiter) Size() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
