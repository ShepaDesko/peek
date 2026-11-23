package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Roles, in increasing order of power. A role is checked by name, never by
// comparing strings elsewhere in the code base.
const (
	RoleAuditor = "auditor" // read the audit trail, nothing else
	RoleMember  = "member"  // create and manage their own secrets
	RoleManager = "manager" // users and policies
	RoleAdmin   = "admin"   // the whole instance
)

// User statuses.
const (
	UserActive   = "active"
	UserInvited  = "invited"
	UserDisabled = "disabled"
)

// ErrUserExists is returned when an address is already taken in the org.
var ErrUserExists = errors.New("store: a user with that address already exists")

// User is an account.
type User struct {
	ID                 string
	OrgID              string
	Email              string
	EmailKey           string
	PasswordHash       string
	DisplayName        string
	Role               string
	Status             string
	MustChangePassword bool
	TOTPSecretEnc      []byte
	TOTPConfirmedAt    time.Time
	FailedLogins       int
	LockedUntil        time.Time
	LastLoginAt        time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	// SSOIssuer and SSOSubject link the account to a directory identity. The
	// pair is the link, not the address: an address is a label that changes,
	// a subject is the directory's own identifier and does not.
	SSOIssuer  string
	SSOSubject string
}

// FromDirectory reports whether the account is linked to an identity provider.
func (u *User) FromDirectory() bool { return u.SSOSubject != "" }

// HasTOTP reports whether a confirmed authenticator is enrolled.
func (u *User) HasTOTP() bool { return len(u.TOTPSecretEnc) > 0 && !u.TOTPConfirmedAt.IsZero() }

// Locked reports whether the account is temporarily locked out.
func (u *User) Locked(now time.Time) bool {
	return !u.LockedUntil.IsZero() && u.LockedUntil.After(now)
}

// Can reports whether the user's role is at least the one required.
func (u *User) Can(required string) bool { return RoleAtLeast(u.Role, required) }

// RoleAtLeast compares two roles by power. auditor is deliberately outside the
// ladder: it is a read-only role, not a weaker administrator.
func RoleAtLeast(have, required string) bool {
	if have == required {
		return true
	}
	rank := map[string]int{RoleMember: 1, RoleManager: 2, RoleAdmin: 3}
	h, okHave := rank[have]
	r, okNeed := rank[required]
	if !okHave || !okNeed {
		return false
	}
	return h >= r
}

// NormalizeEmail lowercases and trims an address for lookups.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateUser inserts an account.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		id, err := newID()
		if err != nil {
			return User{}, err
		}
		u.ID = id
	}
	if u.OrgID == "" {
		u.OrgID = DefaultOrgID
	}
	u.Email = strings.TrimSpace(u.Email)
	u.EmailKey = NormalizeEmail(u.Email)
	if u.EmailKey == "" {
		return User{}, errors.New("store: an account needs an e-mail address")
	}
	if u.Role == "" {
		u.Role = RoleMember
	}
	if u.Status == "" {
		u.Status = UserActive
	}
	now := s.Now()
	u.CreatedAt, u.UpdatedAt = now, now

	_, err := s.exec(ctx, `INSERT INTO users
		(id, org_id, email, email_key, password_hash, display_name, role, status,
		 must_change_password, totp_secret_enc, totp_confirmed_at, failed_logins,
		 locked_until, last_login_at, created_at, updated_at, sso_issuer, sso_subject)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, NULL, NULL, ?, ?, ?, ?)`,
		u.ID, u.OrgID, u.Email, u.EmailKey, nullString(u.PasswordHash), u.DisplayName,
		u.Role, u.Status, boolToInt(u.MustChangePassword), unix(now), unix(now),
		nullString(u.SSOIssuer), nullString(u.SSOSubject))
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUserExists
		}
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	return u, nil
}

const userColumns = `id, org_id, email, email_key, password_hash, display_name, role, status,
	must_change_password, totp_secret_enc, totp_confirmed_at, failed_logins,
	locked_until, last_login_at, created_at, updated_at, sso_issuer, sso_subject`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var (
		u                          User
		passwordHash               nullStr
		mustChange                 int
		totpConfirmed, lockedUntil sql.NullInt64
		lastLogin                  sql.NullInt64
		created, updated           int64
		ssoIssuer, ssoSubject      nullStr
	)
	err := row.Scan(&u.ID, &u.OrgID, &u.Email, &u.EmailKey, &passwordHash, &u.DisplayName,
		&u.Role, &u.Status, &mustChange, &u.TOTPSecretEnc, &totpConfirmed, &u.FailedLogins,
		&lockedUntil, &lastLogin, &created, &updated, &ssoIssuer, &ssoSubject)
	if err != nil {
		return User{}, err
	}
	u.SSOIssuer, u.SSOSubject = ssoIssuer.String, ssoSubject.String
	u.PasswordHash = passwordHash.String
	u.MustChangePassword = mustChange == 1
	if totpConfirmed.Valid {
		u.TOTPConfirmedAt = fromUnix(totpConfirmed.Int64)
	}
	if lockedUntil.Valid {
		u.LockedUntil = fromUnix(lockedUntil.Int64)
	}
	if lastLogin.Valid {
		u.LastLoginAt = fromUnix(lastLogin.Int64)
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(created), fromUnix(updated)
	return u, nil
}

// UserByEmail looks an account up by address within an organisation.
func (s *Store) UserByEmail(ctx context.Context, orgID, email string) (User, error) {
	row := s.queryRow(ctx, `SELECT `+userColumns+` FROM users WHERE org_id = ? AND email_key = ?`,
		orDefaultOrg(orgID), NormalizeEmail(email))
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// UserBySSOSubject looks an account up by its directory identity.
func (s *Store) UserBySSOSubject(ctx context.Context, issuer, subject string) (User, error) {
	if issuer == "" || subject == "" {
		return User{}, ErrNotFound
	}
	row := s.queryRow(ctx, `SELECT `+userColumns+` FROM users WHERE sso_issuer = ? AND sso_subject = ?`,
		issuer, subject)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// LinkSSO attaches a directory identity to an existing account.
//
// The guard matters: the update only applies to a row that is not already
// linked to a *different* subject. Without it, a provider that reused an
// address — or an operator who repointed the instance at another tenant —
// could quietly take over somebody else's account.
func (s *Store) LinkSSO(ctx context.Context, userID, issuer, subject string) (bool, error) {
	res, err := s.exec(ctx, `UPDATE users SET sso_issuer = ?, sso_subject = ?, updated_at = ?
		WHERE id = ? AND (sso_subject IS NULL OR (sso_issuer = ? AND sso_subject = ?))`,
		issuer, subject, unix(s.Now()), userID, issuer, subject)
	if err != nil {
		if isUniqueViolation(err) {
			// Another account already holds this subject.
			return false, nil
		}
		return false, fmt.Errorf("store: link sso identity: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return true, nil //nolint:nilerr // a driver that cannot count: assume it worked
	}
	return n > 0, nil
}

// SetUserEmail changes an address. It fails with ErrUserExists when the new
// one is taken, which is what keeps an address change at the provider from
// signing somebody into the wrong account.
func (s *Store) SetUserEmail(ctx context.Context, userID, email string) error {
	trimmed := strings.TrimSpace(email)
	key := NormalizeEmail(trimmed)
	if key == "" {
		return errors.New("store: an account needs an e-mail address")
	}
	_, err := s.exec(ctx, `UPDATE users SET email = ?, email_key = ?, updated_at = ? WHERE id = ?`,
		trimmed, key, unix(s.Now()), userID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserExists
		}
		return fmt.Errorf("store: change address: %w", err)
	}
	return nil
}

// UnlinkSSO detaches a directory identity, leaving the account local.
func (s *Store) UnlinkSSO(ctx context.Context, userID string) error {
	_, err := s.exec(ctx, `UPDATE users SET sso_issuer = NULL, sso_subject = NULL, updated_at = ?
		WHERE id = ?`, unix(s.Now()), userID)
	if err != nil {
		return fmt.Errorf("store: unlink sso identity: %w", err)
	}
	return nil
}

// UpdateUserIdentity refreshes the display name and role from the directory.
// Both are optional: an empty value leaves the column alone.
func (s *Store) UpdateUserIdentity(ctx context.Context, userID, displayName, role string) error {
	q := `UPDATE users SET updated_at = ?`
	args := []any{unix(s.Now())}
	if displayName != "" {
		q += `, display_name = ?`
		args = append(args, displayName)
	}
	if role != "" {
		q += `, role = ?`
		args = append(args, role)
	}
	q += ` WHERE id = ?`
	args = append(args, userID)
	if _, err := s.exec(ctx, q, args...); err != nil {
		return fmt.Errorf("store: refresh user from the directory: %w", err)
	}
	return nil
}

// UserByID looks an account up by identifier.
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	row := s.queryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns the accounts of an organisation, oldest first.
func (s *Store) ListUsers(ctx context.Context, orgID string) ([]User, error) {
	rows, err := s.query(ctx, `SELECT `+userColumns+` FROM users WHERE org_id = ? ORDER BY created_at`,
		orDefaultOrg(orgID))
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns how many accounts exist, which is what the first-run
// check uses to decide whether an instance still needs its first administrator.
func (s *Store) CountUsers(ctx context.Context, orgID string) (int, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = ?`, orDefaultOrg(orgID)).Scan(&n)
	return n, err
}

// UpdateUserProfile changes the display name, role and status.
func (s *Store) UpdateUserProfile(ctx context.Context, id, displayName, role, status string) error {
	_, err := s.exec(ctx, `UPDATE users SET display_name = ?, role = ?, status = ?, updated_at = ? WHERE id = ?`,
		displayName, role, status, unix(s.Now()), id)
	return err
}

// SetPassword stores a new password hash and clears the change requirement.
func (s *Store) SetPassword(ctx context.Context, id, hash string, mustChange bool) error {
	_, err := s.exec(ctx, `UPDATE users SET password_hash = ?, must_change_password = ?,
		failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`,
		hash, boolToInt(mustChange), unix(s.Now()), id)
	return err
}

// SetUserStatus enables or disables an account.
func (s *Store) SetUserStatus(ctx context.Context, id, status string) error {
	_, err := s.exec(ctx, `UPDATE users SET status = ?, updated_at = ? WHERE id = ?`, status, unix(s.Now()), id)
	return err
}

// RecordLogin resets the failure counter and stamps the last login.
func (s *Store) RecordLogin(ctx context.Context, id string, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE users SET last_login_at = ?, failed_logins = 0, locked_until = NULL,
		status = CASE WHEN status = ? THEN ? ELSE status END, updated_at = ? WHERE id = ?`,
		unix(now), UserInvited, UserActive, unix(now), id)
	return err
}

// RecordFailedLogin increments the counter and locks the account once the
// limit is reached. Locking is temporary on purpose: a permanent lock turns a
// guessing attempt into a denial of service against the real user.
func (s *Store) RecordFailedLogin(ctx context.Context, id string, limit int, lockFor time.Duration, now time.Time) (locked bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var failed int
		if err := tx.QueryRowContext(ctx, s.rebind(`SELECT failed_logins FROM users WHERE id = ?`), id).Scan(&failed); err != nil {
			return err
		}
		failed++
		var until any
		if limit > 0 && failed >= limit {
			until = unix(now.Add(lockFor))
			locked = true
		}
		_, err := tx.ExecContext(ctx, s.rebind(`UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?`),
			failed, until, unix(now), id)
		return err
	})
	return locked, err
}

// SetTOTPSecret stores an encrypted TOTP seed, unconfirmed until the user
// proves they can read a code from it.
func (s *Store) SetTOTPSecret(ctx context.Context, id string, encrypted []byte) error {
	_, err := s.exec(ctx, `UPDATE users SET totp_secret_enc = ?, totp_confirmed_at = NULL, updated_at = ? WHERE id = ?`,
		encrypted, unix(s.Now()), id)
	return err
}

// ConfirmTOTP marks the enrolled authenticator as working.
func (s *Store) ConfirmTOTP(ctx context.Context, id string, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE users SET totp_confirmed_at = ?, updated_at = ? WHERE id = ?`,
		unix(now), unix(now), id)
	return err
}

// DisableTOTP removes the second factor and every recovery code with it.
func (s *Store) DisableTOTP(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE users SET totp_secret_enc = NULL,
			totp_confirmed_at = NULL, updated_at = ? WHERE id = ?`), unix(s.Now()), id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM recovery_codes WHERE user_id = ?`), id)
		return err
	})
}

// DeleteUser removes an account. Secrets keep their creator id, which is a
// dangling reference on purpose: the audit trail must not be rewritten.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// --- recovery codes ---------------------------------------------------------

// ReplaceRecoveryCodes swaps the whole set in one transaction.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte) error {
	now := unix(s.Now())
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM recovery_codes WHERE user_id = ?`), userID); err != nil {
			return err
		}
		for _, h := range hashes {
			id, err := newID()
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO recovery_codes (id, user_id, code_hash, created_at, used_at)
				VALUES (?, ?, ?, ?, NULL)`), id, userID, h, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// UseRecoveryCode marks a matching unused code as spent and reports success.
func (s *Store) UseRecoveryCode(ctx context.Context, userID string, hash []byte, now time.Time) (bool, error) {
	res, err := s.exec(ctx, `UPDATE recovery_codes SET used_at = ?
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`, unix(now), userID, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// CountRecoveryCodes returns how many codes are left unused.
func (s *Store) CountRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}
