// Package secrets holds the secret lifecycle rules: policy validation at
// creation, proof of possession before reveal, and the audit trail that goes
// with both.
//
// It never sees plaintext, a key or a passphrase. Everything it stores arrives
// already sealed by the browser.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// Errors surfaced to the HTTP layer.
var (
	ErrNotFound   = errors.New("secrets: not found")
	ErrBadToken   = errors.New("secrets: wrong key or passphrase")
	ErrLocked     = errors.New("secrets: too many failed attempts, the secret has been destroyed")
	ErrPolicy     = errors.New("secrets: refused by policy")
	ErrConflict   = errors.New("secrets: identifier already used")
	ErrNotAllowed = errors.New("secrets: not allowed")
)

// PolicyError describes which rule refused a creation request.
type PolicyError struct {
	Field  string
	Reason string
}

func (e *PolicyError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Reason) }
func (e *PolicyError) Unwrap() error { return ErrPolicy }

// Service is the secret lifecycle.
type Service struct {
	store *store.Store
	cfg   *config.Config
	nowFn func() time.Time
}

// New builds a Service.
func New(st *store.Store, cfg *config.Config) *Service {
	return &Service{store: st, cfg: cfg, nowFn: time.Now}
}

// SetClock overrides the clock. Tests only.
func (s *Service) SetClock(f func() time.Time) { s.nowFn = f }

func (s *Service) now() time.Time { return s.nowFn().UTC() }

// CreateInput is what the browser submits. Every byte slice here is already
// ciphertext or a hash: the server could not decrypt any of it.
type CreateInput struct {
	ID                   string
	Kind                 string
	Ciphertext           []byte
	ReadTokenHash        []byte
	ReceiptTokenHash     []byte
	KDF                  pcrypto.KDFParams
	HasPassphrase        bool
	TTL                  time.Duration
	Views                int
	RetrievalStep        bool
	DeletableByRecipient bool
	LabelEnc             []byte
	CreatorID            string
	OrgID                string
}

// Created is the server side of a new secret. The links are assembled by the
// client, which alone holds the keys.
type Created struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	ViewsMax  int       `json:"views_max"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	URL       string    `json:"url"`
}

// Create validates the request against the instance policy and stores it.
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	p := s.cfg.Policy

	if !pcrypto.ValidID(in.ID) {
		return Created{}, &PolicyError{Field: "id", Reason: "malformed identifier"}
	}
	if !allowedKind(p.AllowedKinds, in.Kind) {
		return Created{}, &PolicyError{Field: "kind", Reason: fmt.Sprintf("kind %q is not allowed on this instance", in.Kind)}
	}
	if len(in.ReadTokenHash) != 32 || len(in.ReceiptTokenHash) != 32 {
		return Created{}, &PolicyError{Field: "tokens", Reason: "read and receipt token hashes must be 32 bytes"}
	}
	if len(in.Ciphertext) == 0 {
		return Created{}, &PolicyError{Field: "ciphertext", Reason: "empty payload"}
	}
	if int64(len(in.Ciphertext)) > p.MaxSecretBytes {
		return Created{}, &PolicyError{Field: "ciphertext",
			Reason: fmt.Sprintf("payload of %d bytes exceeds the %d byte limit", len(in.Ciphertext), p.MaxSecretBytes)}
	}
	if len(in.KDF.Salt) < pcrypto.SaltLen {
		return Created{}, &PolicyError{Field: "kdf.salt", Reason: "salt too short"}
	}
	if in.KDF.MemoryKiB < 8192 || in.KDF.Iterations < 1 || in.KDF.Parallelism < 1 {
		return Created{}, &PolicyError{Field: "kdf", Reason: "key derivation parameters below the accepted floor"}
	}
	if p.RequirePassphrase && !in.HasPassphrase {
		return Created{}, &PolicyError{Field: "passphrase", Reason: "this instance requires a passphrase"}
	}

	views := in.Views
	if views <= 0 {
		views = p.DefaultViews
	}
	if views > p.MaxViews {
		return Created{}, &PolicyError{Field: "views",
			Reason: fmt.Sprintf("%d views requested, the limit is %d", views, p.MaxViews)}
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = p.DefaultTTL.Std()
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > p.MaxTTL.Std() {
		return Created{}, &PolicyError{Field: "ttl",
			Reason: fmt.Sprintf("expiry of %s requested, the limit is %s", ttl, p.MaxTTL)}
	}

	retrieval := in.RetrievalStep || p.ForceRetrievalStep
	orgID := in.OrgID
	if orgID == "" {
		orgID = "default"
	}
	now := s.now()
	expires := now.Add(ttl)

	err := s.store.Create(ctx, store.NewSecret{
		ID:                   in.ID,
		OrgID:                orgID,
		CreatorID:            in.CreatorID,
		Kind:                 in.Kind,
		Ciphertext:           in.Ciphertext,
		SizeBytes:            int64(len(in.Ciphertext)),
		ReadTokenHash:        in.ReadTokenHash,
		ReceiptTokenHash:     in.ReceiptTokenHash,
		KDF:                  in.KDF,
		HasPassphrase:        in.HasPassphrase,
		RetrievalStep:        retrieval,
		DeletableByRecipient: in.DeletableByRecipient,
		ViewsMax:             views,
		MaxFailedAttempts:    s.cfg.Security.MaxPassphraseTries,
		LabelEnc:             in.LabelEnc,
		ExpiresAt:            expires,
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return Created{}, ErrConflict
	case err != nil:
		return Created{}, err
	}

	return Created{
		ID:        in.ID,
		Kind:      in.Kind,
		ViewsMax:  views,
		ExpiresAt: expires,
		CreatedAt: now,
		URL:       s.cfg.SecretURL(in.ID),
	}, nil
}

// Meta returns what a recipient may see before proving possession of the key.
// Missing, expired and fully consumed secrets are all reported as ErrNotFound,
// so the answer never discloses whether a secret ever existed.
func (s *Service) Meta(ctx context.Context, id string) (store.Meta, error) {
	m, err := s.store.Meta(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Meta{}, ErrNotFound
	}
	return m, err
}

// Reveal checks the read token, consumes one view and returns the ciphertext.
//
// A wrong token costs no view: it increments the failure counter instead, and
// the secret is destroyed once the limit is reached. That is what makes the
// "click to reveal" step robust against link-preview bots and the passphrase
// robust against guessing.
func (s *Service) Reveal(ctx context.Context, id string, readToken []byte) (store.Reveal, int, error) {
	if len(readToken) != 32 {
		return store.Reveal{}, 0, ErrBadToken
	}
	hash := pcrypto.HashReadToken(readToken)
	rev, err := s.store.Consume(ctx, id, hash, s.now())
	switch {
	case err == nil:
		return rev, 0, nil
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrExhausted):
		return store.Reveal{}, 0, ErrNotFound
	case errors.Is(err, store.ErrBadToken):
		left, burned, ferr := s.store.RegisterFailedAttempt(ctx, id, s.now())
		if ferr != nil && !errors.Is(ferr, store.ErrNotFound) {
			return store.Reveal{}, 0, ferr
		}
		if burned {
			return store.Reveal{}, 0, ErrLocked
		}
		return store.Reveal{}, left, ErrBadToken
	default:
		return store.Reveal{}, 0, err
	}
}

// Receipt returns the sender view of a secret.
func (s *Service) Receipt(ctx context.Context, id string, receiptToken []byte) (store.Receipt, error) {
	if len(receiptToken) != 32 {
		return store.Receipt{}, ErrNotFound
	}
	r, err := s.store.ReceiptStatus(ctx, id, pcrypto.HashReadToken(receiptToken))
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrBadToken):
		return store.Receipt{}, ErrNotFound
	case err != nil:
		return store.Receipt{}, err
	}
	return r, nil
}

// Burn destroys a secret on the sender's request.
func (s *Service) Burn(ctx context.Context, id string, receiptToken []byte) error {
	if len(receiptToken) != 32 {
		return ErrNotFound
	}
	err := s.store.Burn(ctx, id, pcrypto.HashReadToken(receiptToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrBadToken):
		return ErrNotFound
	default:
		return err
	}
}

// DeleteByRecipient destroys a secret on the recipient's request, when the
// sender allowed it.
func (s *Service) DeleteByRecipient(ctx context.Context, id string, readToken []byte) error {
	if len(readToken) != 32 {
		return ErrNotFound
	}
	err := s.store.DeleteByRecipient(ctx, id, pcrypto.HashReadToken(readToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrBadToken):
		return ErrNotFound
	default:
		return err
	}
}

// Purge removes expired secrets. Called by the scheduler every minute.
func (s *Service) Purge(ctx context.Context) (int, error) {
	return s.store.PurgeExpired(ctx, s.now())
}

// Store exposes the underlying store for the audit and admin endpoints.
func (s *Service) Store() *store.Store { return s.store }

func allowedKind(allowed []string, kind string) bool {
	if kind == "" {
		return false
	}
	for _, k := range allowed {
		if k == kind {
			return true
		}
	}
	return false
}
