// Package requests implements secret requests: "send me the password for
// account X", where the person asking is the only one who can read the answer.
//
// The requester's browser generates a P-256 key pair. The public half is
// stored here; the private half never leaves the fragment of their own receipt
// link. A depositor seals an ordinary secret and wraps its content key to that
// public key, so neither the server, nor another depositor, nor whoever holds
// the request link can read what was deposited.
//
// Like internal/secrets, this package never sees plaintext or a key.
package requests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/store"
)

// Errors surfaced to the HTTP layer. ErrNotFound covers "never existed",
// "expired" and "already answered" alike, for the same reason it does for
// secrets: the answer must not say which.
var (
	ErrNotFound = errors.New("requests: not found")
	ErrBadToken = errors.New("requests: wrong key")
	ErrClosed   = errors.New("requests: this request has already been answered")
)

// Service is the secret-request lifecycle.
type Service struct {
	store   *store.Store
	cfg     *config.Config
	secrets *secrets.Service
}

// New builds a Service. The secrets service is shared so that a deposit is
// validated by exactly the same policy as a secret created by hand.
func New(st *store.Store, cfg *config.Config, sec *secrets.Service) *Service {
	return &Service{store: st, cfg: cfg, secrets: sec}
}

func (s *Service) now() time.Time { return s.secrets.Now() }

// CreateInput is what the requester's browser submits. Everything is already
// sealed or hashed.
type CreateInput struct {
	ID string
	// BaseURL is the origin the deposit link is built on. See
	// secrets.CreateInput.BaseURL.
	BaseURL          string
	OrgID            string
	CreatorID        string
	PublicKey        []byte
	ReadTokenHash    []byte
	ReceiptTokenHash []byte
	PromptEnc        []byte
	KDF              pcrypto.KDFParams
	LabelEnc         []byte
	NotifyEmailEnc   []byte
	TTL              time.Duration
	MaxDeposits      int
}

// Created is the server side of a new request.
type Created struct {
	ID          string    `json:"id"`
	MaxDeposits int       `json:"max_deposits"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	URL         string    `json:"url"`
}

// Create validates a request against the instance policy and stores it.
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	p := s.cfg.Policy

	if !pcrypto.ValidID(in.ID) {
		return Created{}, &secrets.PolicyError{Field: "id", Reason: "malformed identifier"}
	}
	if !pcrypto.ValidRequestPublicKey(in.PublicKey) {
		return Created{}, &secrets.PolicyError{Field: "public_key",
			Reason: "the public key is not a point on P-256"}
	}
	if len(in.ReadTokenHash) != 32 || len(in.ReceiptTokenHash) != 32 {
		return Created{}, &secrets.PolicyError{Field: "tokens", Reason: "token hashes must be 32 bytes"}
	}
	if len(in.KDF.Salt) < pcrypto.SaltLen {
		return Created{}, &secrets.PolicyError{Field: "kdf.salt", Reason: "salt too short"}
	}
	if in.KDF.MemoryKiB < 8192 || in.KDF.Iterations < 1 || in.KDF.Parallelism < 1 {
		return Created{}, &secrets.PolicyError{Field: "kdf", Reason: "key derivation parameters below the accepted floor"}
	}
	if int64(len(in.PromptEnc)) > p.MaxSecretBytes {
		return Created{}, &secrets.PolicyError{Field: "prompt_enc", Reason: "prompt too large"}
	}

	max := in.MaxDeposits
	if max <= 0 {
		max = p.MaxDeposits
	}
	if max <= 0 {
		max = 1
	}
	limit := p.MaxDeposits
	if limit < 1 {
		limit = 1
	}
	if max > limit {
		return Created{}, &secrets.PolicyError{Field: "max_deposits",
			Reason: fmt.Sprintf("%d deposits requested, the limit is %d", max, limit)}
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = p.DefaultTTL.Std()
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > p.MaxTTL.Std() {
		return Created{}, &secrets.PolicyError{Field: "ttl",
			Reason: fmt.Sprintf("expiry of %s requested, the limit is %s", ttl, p.MaxTTL)}
	}

	orgID := in.OrgID
	if orgID == "" {
		orgID = store.DefaultOrgID
	}
	now := s.now()
	expires := now.Add(ttl)

	err := s.store.CreateRequest(ctx, store.NewRequest{
		ID:               in.ID,
		OrgID:            orgID,
		CreatorID:        in.CreatorID,
		PublicKey:        in.PublicKey,
		ReadTokenHash:    in.ReadTokenHash,
		ReceiptTokenHash: in.ReceiptTokenHash,
		PromptEnc:        in.PromptEnc,
		KDF:              in.KDF,
		LabelEnc:         in.LabelEnc,
		NotifyEmailEnc:   in.NotifyEmailEnc,
		NotifyOnDeposit:  len(in.NotifyEmailEnc) > 0,
		MaxDeposits:      max,
		ExpiresAt:        expires,
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return Created{}, secrets.ErrConflict
	case err != nil:
		return Created{}, err
	}

	return Created{
		ID:          in.ID,
		MaxDeposits: max,
		ExpiresAt:   expires,
		CreatedAt:   now,
		URL:         requestURL(s.cfg, in.BaseURL, in.ID),
	}, nil
}

// requestURL builds the deposit link on the right origin.
func requestURL(cfg *config.Config, base, id string) string {
	if base == "" {
		return cfg.RequestURL(id)
	}
	return strings.TrimRight(base, "/") + "/q/" + id
}

// Meta returns what a depositor may see before proving possession of the key.
func (s *Service) Meta(ctx context.Context, id string) (store.RequestMeta, error) {
	m, err := s.store.RequestMetaByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.RequestMeta{}, ErrNotFound
	}
	return m, err
}

// Open releases the prompt to a depositor who proves possession of the request
// key. Unlike revealing a secret this consumes nothing: a depositor may reload
// the page, and the page is not the answer.
func (s *Service) Open(ctx context.Context, id string, readToken []byte) (store.RequestOpened, error) {
	if len(readToken) != 32 {
		return store.RequestOpened{}, ErrBadToken
	}
	out, err := s.store.OpenRequest(ctx, id, pcrypto.HashReadToken(readToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.RequestOpened{}, ErrNotFound
	case errors.Is(err, store.ErrBadToken):
		return store.RequestOpened{}, ErrBadToken
	}
	return out, err
}

// DepositInput is an answer to a request: an ordinary secret, plus the content
// key wrapped to the requester's public key.
type DepositInput struct {
	Secret secrets.CreateInput
	// WrappedKey is the ECIES box. Its length is fixed by the format, which is
	// the only thing the server can check about it.
	WrappedKey []byte
	ReadToken  []byte
}

// Deposited is what the depositor is told. It carries no link: the depositor
// cannot read back what they deposited, by design.
type Deposited struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	// NotifyEmailEnc is the requester's address, for the notification mail.
	NotifyEmailEnc []byte `json:"-"`
}

// Deposit stores an answer. The counter and the secret move together, so a
// single-use request accepts exactly one answer even with several nodes.
func (s *Service) Deposit(ctx context.Context, requestID string, in DepositInput) (Deposited, error) {
	if len(in.ReadToken) != 32 {
		return Deposited{}, ErrBadToken
	}
	if len(in.WrappedKey) != pcrypto.RequestBoxLen {
		return Deposited{}, &secrets.PolicyError{Field: "wrapped_key",
			Reason: fmt.Sprintf("a wrapped key is %d bytes", pcrypto.RequestBoxLen)}
	}

	now := s.now()
	row, _, err := s.secrets.Prepare(in.Secret, in.Secret.ID, "", now)
	if err != nil {
		return Deposited{}, err
	}
	row.WrappedKey = in.WrappedKey

	claims := make([]store.FileClaim, 0, len(in.Secret.Files))
	for _, c := range in.Secret.Files {
		if !pcrypto.ValidID(c.ID) || len(c.Token) != 32 {
			return Deposited{}, &secrets.PolicyError{Field: "files", Reason: "malformed file reference"}
		}
		claims = append(claims, store.FileClaim{ID: c.ID, TokenHash: pcrypto.HashReadToken(c.Token)})
	}

	target, err := s.store.Deposit(ctx, requestID, pcrypto.HashReadToken(in.ReadToken), row, claims, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Deposited{}, ErrNotFound
	case errors.Is(err, store.ErrBadToken):
		return Deposited{}, ErrBadToken
	case errors.Is(err, store.ErrRequestClosed):
		return Deposited{}, ErrClosed
	case errors.Is(err, store.ErrConflict):
		return Deposited{}, secrets.ErrConflict
	case errors.Is(err, store.ErrNotClaimable):
		return Deposited{}, &secrets.PolicyError{Field: "files",
			Reason: "an attachment is unknown, already used or expired; upload it again"}
	case err != nil:
		return Deposited{}, err
	}

	return Deposited{
		ID:             row.ID,
		CreatedAt:      now,
		NotifyEmailEnc: target.NotifyEmailEnc,
	}, nil
}

// Receipt returns the requester's own view, deposits included.
func (s *Service) Receipt(ctx context.Context, id string, receiptToken []byte) (store.RequestReceipt, error) {
	if len(receiptToken) != 32 {
		return store.RequestReceipt{}, ErrNotFound
	}
	r, err := s.store.RequestReceiptStatus(ctx, id, pcrypto.HashReadToken(receiptToken))
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrBadToken):
		return store.RequestReceipt{}, ErrNotFound
	case err != nil:
		return store.RequestReceipt{}, err
	}
	return r, nil
}

// Close destroys a request. Deposits already made keep their own lifecycle:
// closing the door does not burn what is already inside.
func (s *Service) Close(ctx context.Context, id string, receiptToken []byte) error {
	if len(receiptToken) != 32 {
		return ErrNotFound
	}
	err := s.store.CloseRequest(ctx, id, pcrypto.HashReadToken(receiptToken))
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrBadToken):
		return ErrNotFound
	default:
		return err
	}
}

// List returns a user's own requests, for the dashboard.
func (s *Service) List(ctx context.Context, creatorID string, limit int) ([]store.RequestReceipt, error) {
	return s.store.ListRequests(ctx, creatorID, limit)
}

// Purge removes requests that expired or filled up, once every deposit they
// received is gone.
func (s *Service) Purge(ctx context.Context) (int, error) {
	return s.store.PurgeRequests(ctx, s.now())
}
