package accounts

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// API tokens, for scripts.
//
// The wire format is `peek_<id>.<secret>`:
//
//   - `peek_` is a fixed prefix so secret scanners — GitHub's, GitLab's, or an
//     operator's own grep — can recognise one on sight. A token that leaks into
//     a repository should be findable by the people who look for leaks.
//   - `<id>` is the public half, 128 bits, and the database lookup key. It is
//     stored in the clear, which is what lets a token be revoked by name.
//   - `<secret>` is 256 bits, stored only as SHA-256. Losing the clear text is
//     permanent: the interface shows it once and there is no second chance.
//
// The separator is a dot and not an underscore, which was the first attempt:
// base64url's alphabet contains `_`, so an id with an underscore in it — about
// one in eight — split in the wrong place and the token simply did not work.
// A dot cannot occur in either half.
//
// A token never exceeds its owner's role. It narrows: a deployment script that
// only needs to create secrets gets `secrets:write` and nothing else, even if
// the person who made it is an administrator.
const tokenPrefix = "peek_"

var (
	// ErrBadAPIToken covers a malformed, unknown, revoked or expired token.
	// One error on purpose: the caller learns only that it does not work.
	ErrBadAPIToken = errors.New("accounts: unusable API token")
	// ErrTokenScope is returned when a token lacks the scope a route needs.
	ErrTokenScope = errors.New("accounts: the token does not carry this scope")
)

// IssuedToken is a freshly created token. Secret is the only time the clear
// text exists outside the caller's own storage.
type IssuedToken struct {
	Token  store.APIToken
	Secret string
}

// FormatToken assembles the wire format.
func FormatToken(id string, secret []byte) string {
	return tokenPrefix + id + "." + pcrypto.B64.EncodeToString(secret)
}

// ParseToken splits the wire format back into its halves. It validates shape
// only: whether the token exists is the database's business.
func ParseToken(raw string) (id string, secret []byte, err error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, tokenPrefix) {
		return "", nil, ErrBadAPIToken
	}
	rest := raw[len(tokenPrefix):]
	idPart, secretPart, ok := strings.Cut(rest, ".")
	if !ok || !pcrypto.ValidID(idPart) {
		return "", nil, ErrBadAPIToken
	}
	b, derr := pcrypto.B64.DecodeString(secretPart)
	if derr != nil || len(b) != 32 {
		return "", nil, ErrBadAPIToken
	}
	return idPart, b, nil
}

// CreateToken issues a token for a user.
func (s *Service) CreateToken(ctx context.Context, userID, name string, scopes []string, ttl time.Duration) (IssuedToken, error) {
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return IssuedToken{}, err
	}
	if user.Status != store.UserActive {
		return IssuedToken{}, ErrAccountDisabled
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return IssuedToken{}, errors.New("accounts: a token needs a name")
	}
	if len(name) > 80 {
		return IssuedToken{}, errors.New("accounts: token name too long")
	}
	normalised, err := store.NormaliseScopes(scopes)
	if err != nil {
		return IssuedToken{}, err
	}
	// An auditor may hold a reading token and nothing else: the role is the
	// ceiling, the scopes only narrow it.
	if user.Role == store.RoleAuditor {
		for _, sc := range normalised {
			if sc != store.ScopeAuditRead && sc != store.ScopeInstanceRead {
				return IssuedToken{}, fmt.Errorf("accounts: an auditor account cannot hold the %s scope", sc)
			}
		}
	}

	id, err := pcrypto.NewID()
	if err != nil {
		return IssuedToken{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return IssuedToken{}, err
	}

	var expires time.Time
	if ttl > 0 {
		expires = s.now().Add(ttl)
	}
	err = s.store.CreateAPIToken(ctx, store.NewAPIToken{
		ID:         id,
		OrgID:      user.OrgID,
		UserID:     user.ID,
		Name:       name,
		SecretHash: pcrypto.HashReadToken(secret),
		Scopes:     normalised,
		ExpiresAt:  expires,
	})
	if err != nil {
		return IssuedToken{}, err
	}

	return IssuedToken{
		Token: store.APIToken{
			ID:        id,
			OrgID:     user.OrgID,
			UserID:    user.ID,
			Name:      name,
			Scopes:    normalised,
			CreatedAt: s.now(),
			ExpiresAt: expires,
		},
		Secret: FormatToken(id, secret),
	}, nil
}

// AuthenticateToken resolves a bearer token into a principal.
//
// The returned principal has no session and no CSRF token, which is correct
// and load-bearing: a bearer caller sends no cookie, so there is no
// cross-site request to forge, and the CSRF middleware skips it.
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (*Principal, error) {
	id, secret, err := ParseToken(raw)
	if err != nil {
		return nil, ErrBadAPIToken
	}
	token, err := s.store.AuthenticateAPIToken(ctx, id, secret, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrBadToken):
		return nil, ErrBadAPIToken
	case err != nil:
		return nil, err
	}

	user, err := s.store.UserByID(ctx, token.UserID)
	if err != nil {
		return nil, ErrBadAPIToken
	}
	if user.Status != store.UserActive {
		// Disabling an account must disable its tokens, or offboarding a
		// colleague would leave their scripts running.
		return nil, ErrAccountDisabled
	}
	return &Principal{User: user, Token: &token}, nil
}

// ListTokens returns a user's tokens. An empty userID lists the instance's,
// for an administrator.
func (s *Service) ListTokens(ctx context.Context, userID string) ([]store.APIToken, error) {
	return s.store.ListAPITokens(ctx, userID)
}

// RevokeToken revokes one. userID scopes it to its owner.
func (s *Service) RevokeToken(ctx context.Context, id, userID string) error {
	return s.store.RevokeAPIToken(ctx, id, userID, s.now())
}
