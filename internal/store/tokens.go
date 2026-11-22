package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

// API token scopes. Four, deliberately: a scope nobody can explain is a scope
// nobody sets correctly.
const (
	// ScopeSecretsWrite creates secrets, uploads attachments and opens secret
	// requests — everything a deployment script needs.
	ScopeSecretsWrite = "secrets:write"
	// ScopeSecretsManage reads a sender's own receipts and burns secrets.
	ScopeSecretsManage = "secrets:manage"
	// ScopeAuditRead reads the audit trail. Pairs with the auditor role.
	ScopeAuditRead = "audit:read"
	// ScopeInstanceRead reads instance status, for monitoring.
	ScopeInstanceRead = "instance:read"
)

// AllScopes is every scope a token may carry, in the order the interface
// shows them.
var AllScopes = []string{ScopeSecretsWrite, ScopeSecretsManage, ScopeAuditRead, ScopeInstanceRead}

// ValidScope reports whether s is a known scope.
func ValidScope(s string) bool {
	for _, known := range AllScopes {
		if known == s {
			return true
		}
	}
	return false
}

// NormaliseScopes validates, de-duplicates and orders a scope list, so two
// tokens asking for the same powers store the same string.
func NormaliseScopes(scopes []string) ([]string, error) {
	seen := map[string]bool{}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !ValidScope(s) {
			return nil, fmt.Errorf("store: unknown scope %q", s)
		}
		seen[s] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("store: a token needs at least one scope")
	}
	out := make([]string, 0, len(seen))
	for _, s := range AllScopes {
		if seen[s] {
			out = append(out, s)
		}
	}
	// The loop above already emits them in AllScopes order, which is what
	// makes two equivalent tokens store the same string.
	return out, nil
}

// APIToken is a token as the server knows it. The secret half never appears
// here: only its digest is stored, and only the caller ever held the rest.
type APIToken struct {
	ID         string
	OrgID      string
	UserID     string
	Name       string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// Active reports whether the token may still be used.
func (t APIToken) Active(now time.Time) bool {
	if !t.RevokedAt.IsZero() {
		return false
	}
	return t.ExpiresAt.IsZero() || t.ExpiresAt.After(now)
}

// HasScope reports whether the token carries one of the given scopes.
func (t APIToken) HasScope(wanted ...string) bool {
	for _, w := range wanted {
		for _, s := range t.Scopes {
			if s == w {
				return true
			}
		}
	}
	return false
}

// NewAPIToken is a token being created.
type NewAPIToken struct {
	ID         string
	OrgID      string
	UserID     string
	Name       string
	SecretHash []byte
	Scopes     []string
	ExpiresAt  time.Time
}

// CreateAPIToken stores a token.
func (s *Store) CreateAPIToken(ctx context.Context, n NewAPIToken) error {
	if !pcrypto.ValidID(n.ID) {
		return errors.New("store: malformed token id")
	}
	if len(n.SecretHash) != 32 {
		return errors.New("store: malformed token digest")
	}
	scopes, err := NormaliseScopes(n.Scopes)
	if err != nil {
		return err
	}
	_, err = s.exec(ctx, `INSERT INTO api_tokens
		(id, org_id, user_id, name, secret_hash, scopes, created_at, expires_at, last_used_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
		n.ID, n.OrgID, n.UserID, n.Name, n.SecretHash, strings.Join(scopes, " "),
		unix(s.Now()), unix(n.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: create api token: %w", err)
	}
	return nil
}

func scanToken(row interface {
	Scan(dest ...any) error
}) (APIToken, error) {
	var (
		t        APIToken
		scopes   string
		created  int64
		expires  int64
		lastUsed sql.NullInt64
		revoked  sql.NullInt64
	)
	if err := row.Scan(&t.ID, &t.OrgID, &t.UserID, &t.Name, &scopes,
		&created, &expires, &lastUsed, &revoked); err != nil {
		return APIToken{}, err
	}
	if scopes != "" {
		t.Scopes = strings.Fields(scopes)
	}
	t.CreatedAt = fromUnix(created)
	t.ExpiresAt = fromUnix(expires)
	if lastUsed.Valid {
		t.LastUsedAt = fromUnix(lastUsed.Int64)
	}
	if revoked.Valid {
		t.RevokedAt = fromUnix(revoked.Int64)
	}
	return t, nil
}

//nolint:gosec // G101: a column list, not a credential
const tokenColumns = `id, org_id, user_id, name, scopes, created_at, expires_at, last_used_at, revoked_at`

// AuthenticateAPIToken resolves the public half of a token and checks the
// secret half in constant time.
//
// The digest comparison is constant time and happens after the row is found,
// so a caller learns nothing from timing about which ids exist. A revoked or
// expired token is reported as not found: there is nothing useful to say.
func (s *Store) AuthenticateAPIToken(ctx context.Context, id string, secret []byte, now time.Time) (APIToken, error) {
	if !pcrypto.ValidID(id) || len(secret) != 32 {
		return APIToken{}, ErrNotFound
	}
	var stored []byte
	var t APIToken
	err := s.tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, s.rebind(`SELECT `+tokenColumns+`, secret_hash
			FROM api_tokens WHERE id = ?`), id)
		var (
			scopes            string
			created, expires  int64
			lastUsed, revoked sql.NullInt64
		)
		err := row.Scan(&t.ID, &t.OrgID, &t.UserID, &t.Name, &scopes,
			&created, &expires, &lastUsed, &revoked, &stored)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		t.Scopes = strings.Fields(scopes)
		t.CreatedAt = fromUnix(created)
		t.ExpiresAt = fromUnix(expires)
		if lastUsed.Valid {
			t.LastUsedAt = fromUnix(lastUsed.Int64)
		}
		if revoked.Valid {
			t.RevokedAt = fromUnix(revoked.Int64)
		}

		if !pcrypto.EqualHash(stored, pcrypto.HashReadToken(secret)) {
			return ErrBadToken
		}
		if !t.Active(now) {
			return ErrNotFound
		}

		// Last use is written at most once a minute: a token driving a tight
		// loop would otherwise turn every read into a write, which on SQLite
		// means every read taking the write lock.
		if t.LastUsedAt.IsZero() || now.Sub(t.LastUsedAt) > time.Minute {
			if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`),
				unix(now), id); err != nil {
				return err
			}
			t.LastUsedAt = now
		}
		return nil
	})
	if err != nil {
		return APIToken{}, err
	}
	return t, nil
}

// ListAPITokens returns a user's tokens, newest first. With an empty userID it
// returns every token of the instance, for an administrator.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	query := `SELECT ` + tokenColumns + ` FROM api_tokens`
	args := []any{}
	if userID != "" {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC, id`

	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token unusable. userID scopes the revocation to its
// owner; empty means an administrator revoking anyone's.
func (s *Store) RevokeAPIToken(ctx context.Context, id, userID string, now time.Time) error {
	query := `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`
	args := []any{unix(now), id}
	if userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	res, err := s.exec(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeAPITokens removes tokens that expired or were revoked long enough ago
// that no audit entry still needs their name.
func (s *Store) PurgeAPITokens(ctx context.Context, retention time.Duration, now time.Time) (int, error) {
	cutoff := unix(now.Add(-retention))
	res, err := s.exec(ctx, `DELETE FROM api_tokens
		WHERE (revoked_at IS NOT NULL AND revoked_at <= ?)
		   OR (expires_at != 0 AND expires_at <= ?)`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
