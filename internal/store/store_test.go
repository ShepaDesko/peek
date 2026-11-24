package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

type fixture struct {
	id      string
	read    []byte
	receipt []byte
}

func create(t *testing.T, s *store.Store, views int, ttl time.Duration) fixture {
	t.Helper()
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	kdf, err := pcrypto.DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pcrypto.DeriveKeys(key, "", kdf)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	receiptHash := pcrypto.HashReadToken(receipt)

	sealed, err := pcrypto.Seal(keys.Enc, pcrypto.AAD(id), []byte(`{"v":1,"kind":"text","text":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(context.Background(), store.NewSecret{
		ID:                id,
		OrgID:             "default",
		Kind:              "text",
		Ciphertext:        sealed,
		SizeBytes:         int64(len(sealed)),
		ReadTokenHash:     keys.ReadTokenHash,
		ReceiptTokenHash:  receiptHash,
		KDF:               kdf,
		RetrievalStep:     true,
		ViewsMax:          views,
		MaxFailedAttempts: 5,
		ExpiresAt:         time.Now().Add(ttl),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	return fixture{id: id, read: keys.ReadTokenHash, receipt: receiptHash}
}

func TestCreateMetaConsume(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 1, time.Hour)

		meta, err := s.Meta(ctx, f.id)
		if err != nil {
			t.Fatalf("meta: %v", err)
		}
		if meta.ViewsRemaining != 1 || !meta.RetrievalStep || meta.HasPassphrase {
			t.Fatalf("unexpected metadata: %+v", meta)
		}

		rev, err := s.Consume(ctx, f.id, f.read, time.Now())
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if len(rev.Ciphertext) == 0 || !rev.Destroyed {
			t.Fatalf("unexpected reveal: %+v", rev)
		}

		// Second read must fail, and the row must be gone for good.
		if _, err := s.Consume(ctx, f.id, f.read, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second consume error = %v, want ErrNotFound", err)
		}
		if _, err := s.Meta(ctx, f.id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("meta after consume = %v, want ErrNotFound", err)
		}
		n, err := s.CountActive(ctx)
		if err != nil || n != 0 {
			t.Fatalf("active secrets = %d (err %v), want 0", n, err)
		}

		// The sender can still see what happened.
		r, err := s.ReceiptStatus(ctx, f.id, f.receipt)
		if err != nil {
			t.Fatalf("receipt: %v", err)
		}
		if r.Status != store.StatusViewed || r.ViewsUsed != 1 {
			t.Fatalf("unexpected receipt: %+v", r)
		}
	})
}

func TestWrongReadTokenConsumesNothing(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 1, time.Hour)

		wrong := make([]byte, len(f.read))
		copy(wrong, f.read)
		wrong[0] ^= 0xff

		if _, err := s.Consume(ctx, f.id, wrong, time.Now()); !errors.Is(err, store.ErrBadToken) {
			t.Fatalf("consume with wrong token = %v, want ErrBadToken", err)
		}
		meta, err := s.Meta(ctx, f.id)
		if err != nil {
			t.Fatalf("meta: %v", err)
		}
		if meta.ViewsRemaining != 1 {
			t.Fatalf("a wrong token consumed a view (remaining = %d)", meta.ViewsRemaining)
		}
		// The real token still works afterwards.
		if _, err := s.Consume(ctx, f.id, f.read, time.Now()); err != nil {
			t.Fatalf("consume after failure: %v", err)
		}
	})
}

func TestFailedAttemptsBurnTheSecret(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 1, time.Hour)

		for i := 1; i <= 4; i++ {
			left, burned, err := s.RegisterFailedAttempt(ctx, f.id, time.Now())
			if err != nil {
				t.Fatalf("attempt %d: %v", i, err)
			}
			if burned {
				t.Fatalf("burned after %d attempts, limit is 5", i)
			}
			if left != 5-i {
				t.Fatalf("attempts left = %d, want %d", left, 5-i)
			}
		}
		_, burned, err := s.RegisterFailedAttempt(ctx, f.id, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !burned {
			t.Fatal("fifth wrong attempt did not burn the secret")
		}
		if _, err := s.Consume(ctx, f.id, f.read, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("secret still readable after burn: %v", err)
		}
		r, err := s.ReceiptStatus(ctx, f.id, f.receipt)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != store.StatusLocked {
			t.Fatalf("status = %q, want locked", r.Status)
		}
	})
}

// TestSingleViewUnderConcurrency is the guarantee from section 12 of the spec:
// fifty simultaneous reads of a one-view secret must yield exactly one success.
func TestSingleViewUnderConcurrency(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 1, time.Hour)

		const readers = 50
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			successes int
			otherErrs []error
		)
		start := make(chan struct{})
		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := s.Consume(ctx, f.id, f.read, time.Now())
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					successes++
				case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrExhausted):
				default:
					otherErrs = append(otherErrs, err)
				}
			}()
		}
		close(start)
		wg.Wait()

		if successes != 1 {
			t.Fatalf("%d readers succeeded, want exactly 1", successes)
		}
		if len(otherErrs) > 0 {
			t.Fatalf("unexpected errors: %v", otherErrs)
		}
	})
}

func TestMultiViewSecret(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 3, time.Hour)

		for i := 3; i > 0; i-- {
			rev, err := s.Consume(ctx, f.id, f.read, time.Now())
			if err != nil {
				t.Fatalf("view %d: %v", 4-i, err)
			}
			if rev.ViewsRemaining != i-1 {
				t.Fatalf("remaining = %d, want %d", rev.ViewsRemaining, i-1)
			}
			if rev.Destroyed != (i == 1) {
				t.Fatalf("destroyed = %v at remaining %d", rev.Destroyed, i-1)
			}
		}
		if _, err := s.Consume(ctx, f.id, f.read, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("fourth read = %v, want ErrNotFound", err)
		}
	})
}

func TestExpiryHidesAndPurges(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 5, -time.Minute) // already expired

		if _, err := s.Meta(ctx, f.id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired secret visible: %v", err)
		}
		if _, err := s.Consume(ctx, f.id, f.read, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired secret readable: %v", err)
		}
		n, err := s.PurgeExpired(ctx, time.Now())
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if n != 1 {
			t.Fatalf("purged %d secrets, want 1", n)
		}
		r, err := s.ReceiptStatus(ctx, f.id, f.receipt)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != store.StatusExpired {
			t.Fatalf("status = %q, want expired", r.Status)
		}
	})
}

func TestBurnAndRecipientDelete(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()

		f := create(t, s, 2, time.Hour)
		if err := s.Burn(ctx, f.id, f.receipt, time.Now()); err != nil {
			t.Fatalf("burn: %v", err)
		}
		if _, err := s.Meta(ctx, f.id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("burned secret still live: %v", err)
		}

		// A wrong receipt token must not destroy anything.
		g := create(t, s, 2, time.Hour)
		bad := append([]byte(nil), g.receipt...)
		bad[1] ^= 0xff
		if err := s.Burn(ctx, g.id, bad, time.Now()); !errors.Is(err, store.ErrBadToken) {
			t.Fatalf("burn with wrong token = %v, want ErrBadToken", err)
		}
		if _, err := s.Meta(ctx, g.id); err != nil {
			t.Fatalf("secret destroyed by a wrong token: %v", err)
		}

		// Recipient deletion is refused unless the sender allowed it.
		if err := s.DeleteByRecipient(ctx, g.id, g.read, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("recipient deletion allowed although not permitted: %v", err)
		}
	})
}

func TestMigrationsAreIdempotent(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
		applied, pending, err := s.MigrationStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(applied) == 0 || len(pending) != 0 {
			t.Fatalf("applied = %v, pending = %v", applied, pending)
		}
	})
}

func TestAudit(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 1, time.Hour)

		for _, ev := range []string{store.EventCreated, store.EventPageViewed, store.EventRevealed} {
			if err := s.Append(ctx, store.AuditEvent{
				OrgID: "default", SecretID: f.id, Event: ev, IP: "203.0.113.7", UserAgent: "test",
			}); err != nil {
				t.Fatalf("append %s: %v", ev, err)
			}
		}
		events, err := s.ListAudit(ctx, store.AuditFilter{SecretID: f.id})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 3 {
			t.Fatalf("got %d events, want 3", len(events))
		}
		if events[0].IP != "203.0.113.7" || events[0].SecretID != f.id {
			t.Fatalf("unexpected event: %+v", events[0])
		}

		filtered, err := s.ListAudit(ctx, store.AuditFilter{Event: store.EventRevealed})
		if err != nil {
			t.Fatal(err)
		}
		if len(filtered) != 1 {
			t.Fatalf("filtered = %d, want 1", len(filtered))
		}

		if got := store.AnonymizeIP("203.0.113.7"); got != "203.0.113.0/24" {
			t.Fatalf("AnonymizeIP(v4) = %q", got)
		}
		if got := store.AnonymizeIP("2001:db8:1234:5678::1"); got != "2001:db8:1234::/48" {
			t.Fatalf("AnonymizeIP(v6) = %q", got)
		}

		removed, err := s.PurgeAudit(ctx, time.Nanosecond, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if removed != 3 {
			t.Fatalf("purged %d audit rows, want 3", removed)
		}
	})
}

func TestDuplicateIDRejected(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()
		f := create(t, s, 1, time.Hour)

		err := s.Create(ctx, store.NewSecret{
			ID: f.id, OrgID: "default", Kind: "text", Ciphertext: []byte("x"),
			ReadTokenHash: f.read, ReceiptTokenHash: f.receipt,
			KDF:      pcrypto.KDFParams{Salt: []byte("0123456789abcdef"), MemoryKiB: 19456, Iterations: 2, Parallelism: 1},
			ViewsMax: 1, MaxFailedAttempts: 5, ExpiresAt: time.Now().Add(time.Hour),
		})
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate id error = %v, want ErrConflict", err)
		}
	})
}

// What `peek key rotate` needs before it decides whether rotating is safe.
//
// The command used to tell the operator that "nothing stored today needs
// re-encryption". That was written before the master key had anything to
// protect; it seals second factors and notification addresses now, so the
// sentence had become an invitation to lock every user out of their own
// second factor. The count is what replaced it.
func TestSealedCounts(t *testing.T) {
	run(t, func(t *testing.T, s *store.Store) {
		ctx := context.Background()

		empty, err := s.SealedCounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if empty.Total != 0 {
			t.Fatalf("a fresh instance reports %+v, want nothing sealed", empty)
		}

		user, err := s.CreateUser(ctx, store.User{Email: "admin@acme.test", Role: "admin", Status: "active"})
		if err != nil {
			t.Fatal(err)
		}
		// A user without a second factor is not sealed data.
		if got, err := s.SealedCounts(ctx); err != nil || got.Total != 0 {
			t.Fatalf("an account with no second factor counts as %+v (err %v)", got, err)
		}

		if err := s.SetTOTPSecret(ctx, user.ID, []byte("sealed-totp-seed")); err != nil {
			t.Fatal(err)
		}
		create(t, s, 1, time.Hour)
		createNotified(t, s)

		got, err := s.SealedCounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got.TOTP != 1 {
			t.Errorf("TOTP = %d, want 1", got.TOTP)
		}
		if got.Notify != 1 {
			t.Errorf("Notify = %d, want 1 (the secret without an address must not count)", got.Notify)
		}
		if got.Total != 2 {
			t.Errorf("Total = %d, want 2", got.Total)
		}
	})
}

// createNotified is create() with a notification address, which is the other
// thing the master key seals.
func createNotified(t *testing.T, s *store.Store) {
	t.Helper()
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	kdf, err := pcrypto.DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(context.Background(), store.NewSecret{
		ID:                id,
		OrgID:             "default",
		Kind:              "text",
		Ciphertext:        []byte("x"),
		SizeBytes:         1,
		ReadTokenHash:     []byte("read-token-hash-placeholder-0001"),
		ReceiptTokenHash:  []byte("receipt-token-hash-placeholder01"),
		KDF:               kdf,
		ViewsMax:          1,
		MaxFailedAttempts: 5,
		ExpiresAt:         time.Now().Add(time.Hour),
		NotifyEmailEnc:    []byte("sealed-address"),
		NotifyOnView:      true,
	}); err != nil {
		t.Fatalf("create with a notification address: %v", err)
	}
}
