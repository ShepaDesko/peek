package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Passkey is a registered WebAuthn credential.
//
// Nothing here is a secret: a public key, a credential id and a counter. The
// private half never leaves the authenticator, which is the whole point.
type Passkey struct {
	ID             string
	UserID         string
	CredentialID   []byte
	PublicKey      []byte
	Attestation    string
	AAGUID         []byte
	SignCount      uint32
	Transports     string
	Name           string
	BackupEligible bool
	BackedUp       bool
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// CreatePasskey registers a credential.
func (s *Store) CreatePasskey(ctx context.Context, k Passkey) (Passkey, error) {
	if k.ID == "" {
		id, err := newID()
		if err != nil {
			return Passkey{}, err
		}
		k.ID = id
	}
	now := s.Now()
	k.CreatedAt = now
	_, err := s.exec(ctx, `INSERT INTO passkeys
		(id, user_id, credential_id, public_key, attestation, aaguid, sign_count,
		 transports, name, backup_eligible, backed_up, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		k.ID, k.UserID, k.CredentialID, k.PublicKey, nullString(k.Attestation), k.AAGUID,
		int64(k.SignCount), nullString(k.Transports), k.Name,
		boolToInt(k.BackupEligible), boolToInt(k.BackedUp), unix(now))
	if err != nil {
		if isUniqueViolation(err) {
			return Passkey{}, fmt.Errorf("store: this security key is already registered")
		}
		return Passkey{}, fmt.Errorf("store: register passkey: %w", err)
	}
	return k, nil
}

//nolint:gosec // G101: a list of column names
const passkeyColumns = `id, user_id, credential_id, public_key, attestation, aaguid,
	sign_count, transports, name, backup_eligible, backed_up, created_at, last_used_at`

func scanPasskey(row interface{ Scan(...any) error }) (Passkey, error) {
	var (
		k                       Passkey
		attestation, transports nullStr
		signCount, created      int64
		eligible, backedUp      int
		lastUsed                sql.NullInt64
	)
	err := row.Scan(&k.ID, &k.UserID, &k.CredentialID, &k.PublicKey, &attestation, &k.AAGUID,
		&signCount, &transports, &k.Name, &eligible, &backedUp, &created, &lastUsed)
	if err != nil {
		return Passkey{}, err
	}
	k.Attestation, k.Transports = attestation.String, transports.String
	if signCount > 0 {
		k.SignCount = uint32(signCount) //nolint:gosec // stored from a uint32
	}
	k.BackupEligible, k.BackedUp = eligible == 1, backedUp == 1
	k.CreatedAt = fromUnix(created)
	if lastUsed.Valid {
		k.LastUsedAt = fromUnix(lastUsed.Int64)
	}
	return k, nil
}

// PasskeysForUser lists the credentials of an account.
func (s *Store) PasskeysForUser(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := s.query(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list passkeys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Passkey
	for rows.Next() {
		k, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// PasskeyByCredential finds a credential by its raw identifier.
func (s *Store) PasskeyByCredential(ctx context.Context, credentialID []byte) (Passkey, error) {
	k, err := scanPasskey(s.queryRow(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE credential_id = ?`, credentialID))
	if errors.Is(err, sql.ErrNoRows) {
		return Passkey{}, ErrNotFound
	}
	return k, err
}

// UpdatePasskeyUsage records a successful authentication.
//
// The signature counter is how an authenticator reports cloning: it must never
// go backwards. The caller compares, this only stores.
func (s *Store) UpdatePasskeyUsage(ctx context.Context, id string, signCount uint32, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`,
		int64(signCount), unix(now), id)
	return err
}

// RenamePasskey changes the label shown to the user.
func (s *Store) RenamePasskey(ctx context.Context, userID, id, name string) error {
	res, err := s.exec(ctx, `UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?`, name, id, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes a credential belonging to a user.
func (s *Store) DeletePasskey(ctx context.Context, userID, id string) error {
	res, err := s.exec(ctx, `DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// --- WebAuthn challenges -----------------------------------------------------

// SaveChallenge stores a short-lived WebAuthn session.
func (s *Store) SaveChallenge(ctx context.Context, id, userID, kind, data string, expires time.Time) error {
	_, err := s.exec(ctx, `INSERT INTO webauthn_challenges (id, user_id, kind, data, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, nullString(userID), kind, data, unix(s.Now()), unix(expires))
	return err
}

// TakeChallenge returns a challenge and deletes it, so it cannot be replayed.
func (s *Store) TakeChallenge(ctx context.Context, id, kind string, now time.Time) (userID, data string, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var (
			user    nullStr
			payload string
			expires int64
		)
		row := tx.QueryRowContext(ctx, s.rebind(`SELECT user_id, data, expires_at
			FROM webauthn_challenges WHERE id = ? AND kind = ?`), id, kind)
		if err := row.Scan(&user, &payload, &expires); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM webauthn_challenges WHERE id = ?`), id); err != nil {
			return err
		}
		if fromUnix(expires).Before(now) {
			return ErrNotFound
		}
		userID, data = user.String, payload
		return nil
	})
	return userID, data, err
}

// PurgeChallenges removes expired WebAuthn challenges.
func (s *Store) PurgeChallenges(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM webauthn_challenges WHERE expires_at < ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
