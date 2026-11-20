package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DefaultOrgID is the single organisation of a single-tenant instance.
const DefaultOrgID = "default"

// Session is a signed-in browser.
//
// The row is keyed by SHA-256 of the cookie value: the server can recognise a
// cookie it is shown, but a stolen database gives nobody a usable session.
type Session struct {
	ID                string // SHA-256(cookie), hex
	UserID            string
	OrgID             string
	CSRFHash          []byte
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	IP                string
	UserAgent         string
	MFAPending        bool
	RevokedAt         time.Time
}

// Active reports whether the session may still be used.
func (s Session) Active(now time.Time) bool {
	return s.RevokedAt.IsZero() && s.ExpiresAt.After(now) && s.AbsoluteExpiresAt.After(now)
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	if sess.OrgID == "" {
		sess.OrgID = DefaultOrgID
	}
	_, err := s.exec(ctx, `INSERT INTO sessions
		(id, user_id, org_id, csrf_hash, created_at, last_seen_at, expires_at,
		 absolute_expires_at, ip, user_agent, mfa_pending, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		sess.ID, sess.UserID, sess.OrgID, sess.CSRFHash,
		unix(sess.CreatedAt), unix(sess.LastSeenAt), unix(sess.ExpiresAt), unix(sess.AbsoluteExpiresAt),
		nullString(sess.IP), nullString(truncate(sess.UserAgent, 512)), boolToInt(sess.MFAPending))
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

const sessionColumns = `id, user_id, org_id, csrf_hash, created_at, last_seen_at,
	expires_at, absolute_expires_at, ip, user_agent, mfa_pending, revoked_at`

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var (
		sess                                       Session
		ip, ua                                     nullStr
		created, lastSeen, expires, absoluteExpire int64
		pending                                    int
		revoked                                    sql.NullInt64
	)
	err := row.Scan(&sess.ID, &sess.UserID, &sess.OrgID, &sess.CSRFHash,
		&created, &lastSeen, &expires, &absoluteExpire, &ip, &ua, &pending, &revoked)
	if err != nil {
		return Session{}, err
	}
	sess.CreatedAt = fromUnix(created)
	sess.LastSeenAt = fromUnix(lastSeen)
	sess.ExpiresAt = fromUnix(expires)
	sess.AbsoluteExpiresAt = fromUnix(absoluteExpire)
	sess.IP, sess.UserAgent = ip.String, ua.String
	sess.MFAPending = pending == 1
	if revoked.Valid {
		sess.RevokedAt = fromUnix(revoked.Int64)
	}
	return sess, nil
}

// Session returns a session by its hashed identifier.
func (s *Store) Session(ctx context.Context, id string) (Session, error) {
	sess, err := scanSession(s.queryRow(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

// TouchSession slides the idle expiry forward.
func (s *Store) TouchSession(ctx context.Context, id string, lastSeen, expires time.Time) error {
	_, err := s.exec(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		unix(lastSeen), unix(expires), id)
	return err
}

// PromoteSession clears the pending second factor after a successful check.
func (s *Store) PromoteSession(ctx context.Context, id string, expires time.Time) error {
	_, err := s.exec(ctx, `UPDATE sessions SET mfa_pending = 0, expires_at = ? WHERE id = ?`, unix(expires), id)
	return err
}

// RevokeSession ends one session.
func (s *Store) RevokeSession(ctx context.Context, id string, now time.Time) error {
	_, err := s.exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, unix(now), id)
	return err
}

// RevokeUserSessions ends every session of a user, optionally keeping one.
// Changing a password, disabling an account or removing a second factor all
// go through here: a credential change that leaves old sessions alive is not
// a credential change.
func (s *Store) RevokeUserSessions(ctx context.Context, userID, keepID string, now time.Time) (int64, error) {
	query := `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
	args := []any{unix(now), userID}
	if keepID != "" {
		query += ` AND id != ?`
		args = append(args, keepID)
	}
	res, err := s.exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListSessions returns the live sessions of a user, most recent first.
func (s *Store) ListSessions(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	rows, err := s.query(ctx, `SELECT `+sessionColumns+` FROM sessions
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY last_seen_at DESC`, userID, unix(now))
	if err != nil {
		return nil, fmt.Errorf("store: list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// PurgeExpiredSessions deletes sessions nobody can use any more. Revoked ones
// linger for a day so that "signed out everywhere" stays visible in support.
func (s *Store) PurgeExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM sessions
		WHERE absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
		unix(now), unix(now.Add(-24*time.Hour)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
