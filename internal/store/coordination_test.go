package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/store"
)

// TestJobLockGivesTheJobToExactlyOneNode is the multi-node guarantee for the
// periodic jobs: whichever node wakes up first does the work, the others skip.
func TestJobLockGivesTheJobToExactlyOneNode(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		now := time.Now()

		first, err := s.TryLock(ctx, "purge", "node-a", time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		if !first {
			t.Fatal("the first node did not get the lock")
		}

		second, err := s.TryLock(ctx, "purge", "node-b", time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		if second {
			t.Fatal("two nodes hold the same lock")
		}

		// The holder may renew its own lock without losing it.
		again, err := s.TryLock(ctx, "purge", "node-a", time.Minute, now.Add(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if !again {
			t.Fatal("the holder could not renew its own lock")
		}

		// An expired lock is taken over: a node that died must not block the rest.
		stolen, err := s.TryLock(ctx, "purge", "node-b", time.Minute, now.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if !stolen {
			t.Fatal("an expired lock was not taken over")
		}

		if err := s.Unlock(ctx, "purge", "node-a"); err != nil {
			t.Fatal(err)
		}
		// node-a no longer holds it, so the delete must not have released node-b's.
		free, err := s.TryLock(ctx, "purge", "node-c", time.Minute, now.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if free {
			t.Fatal("unlocking as the wrong holder released the lock")
		}
	})
}

func TestJobLockUnderConcurrency(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		now := time.Now()

		const nodes = 20
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			winners int
		)
		start := make(chan struct{})
		for i := 0; i < nodes; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				ok, err := s.TryLock(ctx, "nightly", holderName(i), time.Minute, now)
				if err != nil {
					return
				}
				if ok {
					mu.Lock()
					winners++
					mu.Unlock()
				}
			}(i)
		}
		close(start)
		wg.Wait()

		if winners != 1 {
			t.Fatalf("%d nodes claimed the lock, want exactly 1", winners)
		}
	})
}

func holderName(i int) string {
	return "node-" + string(rune('a'+i%26))
}

// TestSharedRateLimit checks the bucket several nodes share through the
// database: the burst is spent once, not once per node.
func TestSharedRateLimit(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		now := time.Now()

		const burst = 3
		allowed := 0
		for i := 0; i < 6; i++ {
			ok, err := s.RateAllow(ctx, "read:203.0.113.5", burst, 0, now)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				allowed++
			}
		}
		if allowed != burst {
			t.Fatalf("%d requests allowed, want %d", allowed, burst)
		}

		// A different client has its own bucket.
		ok, err := s.RateAllow(ctx, "read:198.51.100.9", burst, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("a different client was limited by someone else's bucket")
		}

		// Tokens come back over time.
		ok, err = s.RateAllow(ctx, "read:203.0.113.5", burst, 1, now.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("the bucket did not refill")
		}

		removed, err := s.PurgeRateLimits(ctx, time.Second, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if removed == 0 {
			t.Fatal("idle buckets were not purged")
		}
	})
}

func TestSharedRateLimitIsAtomic(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		now := time.Now()

		const burst = 5
		const callers = 40
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			allowed int
		)
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ok, err := s.RateAllow(ctx, "login:10.0.0.1", burst, 0, now)
				if err != nil {
					return
				}
				if ok {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()

		if allowed != burst {
			t.Fatalf("%d callers allowed through a burst of %d", allowed, burst)
		}
	})
}
