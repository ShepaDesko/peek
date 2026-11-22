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
	"github.com/ShepaDesko/peek/internal/storage"
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
	store   *store.Store
	cfg     *config.Config
	storage storage.Backend
	nowFn   func() time.Time
}

// New builds a Service.
func New(st *store.Store, cfg *config.Config) *Service {
	return &Service{store: st, cfg: cfg, nowFn: time.Now}
}

// SetClock overrides the clock. Tests only.
func (s *Service) SetClock(f func() time.Time) { s.nowFn = f }

func (s *Service) now() time.Time { return s.nowFn().UTC() }

// Now is the service clock, shared with the request service so both agree on
// expiry in tests.
func (s *Service) Now() time.Time { return s.now() }

// Config is the instance configuration the policy comes from.
func (s *Service) Config() *config.Config { return s.cfg }

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
	// NotifyEmailEnc is the sender's address, already encrypted by the caller
	// with the server master key.
	NotifyEmailEnc []byte
	NotifyOnView   bool
	// Files are blobs already uploaded and waiting to be claimed. Every
	// recipient of the bundle shares them: one upload, N links.
	Files []FileClaim
}

// FileClaim names an uploaded blob and proves the caller is its uploader.
type FileClaim struct {
	ID    string
	Token []byte
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
	// BundleID is shared by every link of a multi-recipient secret. Senders
	// never need it; it is here because the audit trail does.
	BundleID string `json:"bundle_id,omitempty"`
}

// Create validates one secret against the instance policy and stores it.
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	out, err := s.CreateMany(ctx, []CreateInput{in})
	if err != nil {
		return Created{}, err
	}
	return out[0], nil
}

// CreateMany creates the links of one bundle: several recipients, each with
// its own key, expiry, view count, passphrase and audit trail, all sharing the
// files uploaded once.
//
// It is all-or-nothing. A partially created bundle would hand a recipient a
// link whose attachments were never attached, which looks to them exactly like
// a corrupted secret.
func (s *Service) CreateMany(ctx context.Context, ins []CreateInput) ([]Created, error) {
	p := s.cfg.Policy
	if len(ins) == 0 {
		return nil, &PolicyError{Field: "recipients", Reason: "no recipient"}
	}
	maxRecipients := p.MaxRecipients
	if maxRecipients < 1 {
		maxRecipients = 1
	}
	if len(ins) > maxRecipients {
		return nil, &PolicyError{Field: "recipients",
			Reason: fmt.Sprintf("%d recipients requested, the limit is %d", len(ins), maxRecipients)}
	}

	// Files are a property of the bundle, so they are declared once, on the
	// first recipient. Accepting them anywhere else would silently drop them.
	claims := ins[0].Files
	maxFiles := p.MaxFilesPerSecret
	if maxFiles < 1 {
		maxFiles = 10
	}
	if len(claims) > maxFiles {
		return nil, &PolicyError{Field: "files",
			Reason: fmt.Sprintf("%d files requested, the limit is %d", len(claims), maxFiles)}
	}
	for _, other := range ins[1:] {
		if len(other.Files) > 0 {
			return nil, &PolicyError{Field: "files",
				Reason: "attachments belong to the bundle; declare them once, on the first recipient"}
		}
	}

	now := s.now()
	bundleID := ins[0].ID
	groupID := ""
	if len(ins) > 1 {
		groupID = bundleID
	}

	rows := make([]store.NewSecret, 0, len(ins))
	out := make([]Created, 0, len(ins))
	seen := map[string]bool{}
	for _, in := range ins {
		row, created, err := s.Prepare(in, bundleID, groupID, now)
		if err != nil {
			return nil, err
		}
		if seen[row.ID] {
			return nil, ErrConflict
		}
		seen[row.ID] = true
		rows = append(rows, row)
		out = append(out, created)
	}

	storeClaims := make([]store.FileClaim, 0, len(claims))
	for _, c := range claims {
		if !pcrypto.ValidID(c.ID) || len(c.Token) != 32 {
			return nil, &PolicyError{Field: "files", Reason: "malformed file reference"}
		}
		storeClaims = append(storeClaims, store.FileClaim{
			ID:        c.ID,
			TokenHash: pcrypto.HashReadToken(c.Token),
		})
	}

	err := s.store.CreateBundle(ctx, rows, storeClaims)
	switch {
	case errors.Is(err, store.ErrConflict):
		return nil, ErrConflict
	case errors.Is(err, store.ErrNotClaimable):
		return nil, &PolicyError{Field: "files",
			Reason: "an attachment is unknown, already used or expired; upload it again"}
	case err != nil:
		return nil, err
	}
	return out, nil
}

// Prepare validates one secret against the policy and turns it into a row,
// without storing anything. The deposit path of a secret request uses it, so
// that a deposit is bound by the same policy as any other secret and the two
// cannot drift apart.
func (s *Service) Prepare(in CreateInput, bundleID, groupID string, now time.Time) (store.NewSecret, Created, error) {
	p := s.cfg.Policy

	if !pcrypto.ValidID(in.ID) {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "id", Reason: "malformed identifier"}
	}
	if !allowedKind(p.AllowedKinds, in.Kind) {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "kind", Reason: fmt.Sprintf("kind %q is not allowed on this instance", in.Kind)}
	}
	if len(in.ReadTokenHash) != 32 || len(in.ReceiptTokenHash) != 32 {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "tokens", Reason: "read and receipt token hashes must be 32 bytes"}
	}
	if len(in.Ciphertext) == 0 {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "ciphertext", Reason: "empty payload"}
	}
	if int64(len(in.Ciphertext)) > p.MaxSecretBytes {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "ciphertext",
			Reason: fmt.Sprintf("payload of %d bytes exceeds the %d byte limit", len(in.Ciphertext), p.MaxSecretBytes)}
	}
	if len(in.KDF.Salt) < pcrypto.SaltLen {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "kdf.salt", Reason: "salt too short"}
	}
	if in.KDF.MemoryKiB < 8192 || in.KDF.Iterations < 1 || in.KDF.Parallelism < 1 {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "kdf", Reason: "key derivation parameters below the accepted floor"}
	}
	if p.RequirePassphrase && !in.HasPassphrase {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "passphrase", Reason: "this instance requires a passphrase"}
	}

	views := in.Views
	if views <= 0 {
		views = p.DefaultViews
	}
	if views > p.MaxViews {
		return store.NewSecret{}, Created{}, &PolicyError{Field: "views",
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
		return store.NewSecret{}, Created{}, &PolicyError{Field: "ttl",
			Reason: fmt.Sprintf("expiry of %s requested, the limit is %s", ttl, p.MaxTTL)}
	}

	retrieval := in.RetrievalStep || p.ForceRetrievalStep
	orgID := in.OrgID
	if orgID == "" {
		orgID = "default"
	}
	expires := now.Add(ttl)
	if bundleID == "" {
		bundleID = in.ID
	}

	return store.NewSecret{
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
			GroupID:              groupID,
			BundleID:             bundleID,
			ExpiresAt:            expires,
			NotifyEmailEnc:       in.NotifyEmailEnc,
			NotifyOnView:         in.NotifyOnView,
		}, Created{
			ID:        in.ID,
			Kind:      in.Kind,
			ViewsMax:  views,
			ExpiresAt: expires,
			CreatedAt: now,
			URL:       s.cfg.SecretURL(in.ID),
			BundleID:  bundleID,
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
