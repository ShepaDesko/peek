package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Invitation is a pending account.
//
// Only the SHA-256 of the invitation token is stored, so the link that was
// e-mailed cannot be recovered from a database dump.
type Invitation struct {
	ID             string
	OrgID          string
	Email          string
	EmailKey       string
	Role           string
	TokenHash      []byte
	InvitedBy      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	AcceptedAt     time.Time
	AcceptedUserID string
}

// Pending reports whether the invitation can still be used.
func (i Invitation) Pending(now time.Time) bool {
	return i.AcceptedAt.IsZero() && i.ExpiresAt.After(now)
}

// CreateInvitation stores an invitation, replacing any pending one for the
// same address so that re-inviting someone simply issues a new link.
func (s *Store) CreateInvitation(ctx context.Context, inv Invitation) (Invitation, error) {
	if inv.ID == "" {
		id, err := newID()
		if err != nil {
			return Invitation{}, err
		}
		inv.ID = id
	}
	if inv.OrgID == "" {
		inv.OrgID = DefaultOrgID
	}
	inv.EmailKey = NormalizeEmail(inv.Email)
	if inv.Role == "" {
		inv.Role = RoleMember
	}
	now := s.Now()
	inv.CreatedAt = now

	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM invitations
			WHERE org_id = ? AND email_key = ? AND accepted_at IS NULL`), inv.OrgID, inv.EmailKey); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO invitations
			(id, org_id, email, email_key, role, token_hash, invited_by, created_at, expires_at, accepted_at, accepted_user_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`),
			inv.ID, inv.OrgID, inv.Email, inv.EmailKey, inv.Role, inv.TokenHash,
			nullString(inv.InvitedBy), unix(now), unix(inv.ExpiresAt))
		return err
	})
	if err != nil {
		return Invitation{}, fmt.Errorf("store: create invitation: %w", err)
	}
	return inv, nil
}

const invitationColumns = `id, org_id, email, email_key, role, token_hash, invited_by,
	created_at, expires_at, accepted_at, accepted_user_id`

func scanInvitation(row interface{ Scan(...any) error }) (Invitation, error) {
	var (
		inv                     Invitation
		invitedBy, acceptedUser nullStr
		created, expires        int64
		accepted                sql.NullInt64
	)
	err := row.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.EmailKey, &inv.Role, &inv.TokenHash,
		&invitedBy, &created, &expires, &accepted, &acceptedUser)
	if err != nil {
		return Invitation{}, err
	}
	inv.InvitedBy, inv.AcceptedUserID = invitedBy.String, acceptedUser.String
	inv.CreatedAt, inv.ExpiresAt = fromUnix(created), fromUnix(expires)
	if accepted.Valid {
		inv.AcceptedAt = fromUnix(accepted.Int64)
	}
	return inv, nil
}

// InvitationByToken looks up a pending invitation by its hashed token.
func (s *Store) InvitationByToken(ctx context.Context, tokenHash []byte) (Invitation, error) {
	inv, err := scanInvitation(s.queryRow(ctx,
		`SELECT `+invitationColumns+` FROM invitations WHERE token_hash = ?`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	return inv, err
}

// ListInvitations returns the pending invitations of an organisation.
func (s *Store) ListInvitations(ctx context.Context, orgID string, now time.Time) ([]Invitation, error) {
	rows, err := s.query(ctx, `SELECT `+invitationColumns+` FROM invitations
		WHERE org_id = ? AND accepted_at IS NULL AND expires_at > ? ORDER BY created_at DESC`,
		orDefaultOrg(orgID), unix(now))
	if err != nil {
		return nil, fmt.Errorf("store: list invitations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Invitation
	for rows.Next() {
		inv, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// AcceptInvitation marks an invitation as used by a user, once.
func (s *Store) AcceptInvitation(ctx context.Context, id, userID string, now time.Time) error {
	res, err := s.exec(ctx, `UPDATE invitations SET accepted_at = ?, accepted_user_id = ?
		WHERE id = ? AND accepted_at IS NULL`, unix(now), userID, id)
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

// DeleteInvitation withdraws a pending invitation.
func (s *Store) DeleteInvitation(ctx context.Context, orgID, id string) error {
	res, err := s.exec(ctx, `DELETE FROM invitations WHERE id = ? AND org_id = ? AND accepted_at IS NULL`,
		id, orDefaultOrg(orgID))
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

// PurgeInvitations removes expired invitations.
func (s *Store) PurgeInvitations(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM invitations WHERE accepted_at IS NULL AND expires_at < ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- password resets ---------------------------------------------------------

// PasswordReset is a pending reset link.
type PasswordReset struct {
	ID        string
	UserID    string
	TokenHash []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

// CreatePasswordReset stores a reset request, replacing any earlier one.
func (s *Store) CreatePasswordReset(ctx context.Context, userID string, tokenHash []byte, expires time.Time) (PasswordReset, error) {
	id, err := newID()
	if err != nil {
		return PasswordReset{}, err
	}
	now := s.Now()
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL`), userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO password_resets
			(id, user_id, token_hash, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)`),
			id, userID, tokenHash, unix(now), unix(expires))
		return err
	})
	if err != nil {
		return PasswordReset{}, fmt.Errorf("store: create password reset: %w", err)
	}
	return PasswordReset{ID: id, UserID: userID, TokenHash: tokenHash, CreatedAt: now, ExpiresAt: expires}, nil
}

// UsePasswordReset consumes a reset token and returns the user it belongs to.
func (s *Store) UsePasswordReset(ctx context.Context, tokenHash []byte, now time.Time) (string, error) {
	var userID string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var (
			id      string
			expires int64
		)
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT id, user_id, expires_at FROM password_resets
			WHERE token_hash = ? AND used_at IS NULL`), tokenHash).Scan(&id, &userID, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if fromUnix(expires).Before(now) {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, s.rebind(`UPDATE password_resets SET used_at = ? WHERE id = ?`), unix(now), id)
		return err
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}
