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

// Secret status values used by tombstones and the receipt page.
const (
	StatusActive  = "active"
	StatusViewed  = "viewed" // all views consumed
	StatusExpired = "expired"
	StatusBurned  = "burned"  // destroyed by the sender
	StatusDeleted = "deleted" // destroyed by the recipient
	StatusLocked  = "locked"  // too many wrong passphrase attempts
)

// NewSecret is everything the server needs to persist a freshly created secret.
// The caller has already validated it against the policy.
type NewSecret struct {
	ID                   string
	OrgID                string
	CreatorID            string
	Kind                 string
	Ciphertext           []byte
	StorageRef           string
	SizeBytes            int64
	ReadTokenHash        []byte
	ReceiptTokenHash     []byte
	KDF                  pcrypto.KDFParams
	HasPassphrase        bool
	RetrievalStep        bool
	DeletableByRecipient bool
	ViewsMax             int
	MaxFailedAttempts    int
	LabelEnc             []byte
	GroupID              string
	ExpiresAt            time.Time
}

// Meta is the public metadata a recipient may read before proving possession
// of the key. It deliberately contains nothing about the content.
type Meta struct {
	ID             string
	Kind           string
	HasPassphrase  bool
	RetrievalStep  bool
	Deletable      bool
	KDF            pcrypto.KDFParams
	ViewsRemaining int
	ViewsMax       int
	ExpiresAt      time.Time
	CreatedAt      time.Time
	SizeBytes      int64
	AttemptsLeft   int
}

// Receipt is the sender-side view of a secret, alive or not.
type Receipt struct {
	ID             string
	Status         string
	ViewsUsed      int
	ViewsMax       int
	ViewsRemaining int
	ExpiresAt      time.Time
	CreatedAt      time.Time
	LastViewedAt   time.Time
	HasPassphrase  bool
	Kind           string
}

// Create inserts a secret. A duplicate identifier is a conflict, never an
// overwrite: identifiers are generated client side and must stay unique.
func (s *Store) Create(ctx context.Context, n NewSecret) error {
	if !pcrypto.ValidID(n.ID) {
		return errors.New("store: malformed secret id")
	}
	now := unix(s.Now())
	_, err := s.exec(ctx, `INSERT INTO secrets (
		id, org_id, creator_id, kind, ciphertext, storage_ref, size_bytes,
		read_token_hash, receipt_token_hash,
		kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism,
		has_passphrase, retrieval_step, deletable_by_recipient,
		views_max, views_remaining, failed_attempts, max_failed_attempts,
		label_enc, group_id, created_at, expires_at, last_viewed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, NULL)`,
		n.ID, n.OrgID, nullString(n.CreatorID), n.Kind, n.Ciphertext, nullString(n.StorageRef), n.SizeBytes,
		n.ReadTokenHash, n.ReceiptTokenHash,
		n.KDF.Salt, n.KDF.MemoryKiB, n.KDF.Iterations, n.KDF.Parallelism,
		boolToInt(n.HasPassphrase), boolToInt(n.RetrievalStep), boolToInt(n.DeletableByRecipient),
		n.ViewsMax, n.ViewsMax, n.MaxFailedAttempts,
		n.LabelEnc, nullString(n.GroupID), now, unix(n.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: create secret: %w", err)
	}
	return nil
}

// Meta returns the public metadata of a live secret. An expired secret is
// reported as not found, exactly like one that never existed.
func (s *Store) Meta(ctx context.Context, id string) (Meta, error) {
	if !pcrypto.ValidID(id) {
		return Meta{}, ErrNotFound
	}
	var (
		m                  Meta
		hasPass, step, del int
		expires, created   int64
		failed, maxFailed  int
	)
	err := s.queryRow(ctx, `SELECT id, kind, has_passphrase, retrieval_step, deletable_by_recipient,
		kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism,
		views_remaining, views_max, failed_attempts, max_failed_attempts,
		size_bytes, created_at, expires_at
		FROM secrets WHERE id = ?`, id).Scan(
		&m.ID, &m.Kind, &hasPass, &step, &del,
		&m.KDF.Salt, &m.KDF.MemoryKiB, &m.KDF.Iterations, &m.KDF.Parallelism,
		&m.ViewsRemaining, &m.ViewsMax, &failed, &maxFailed,
		&m.SizeBytes, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Meta{}, ErrNotFound
	}
	if err != nil {
		return Meta{}, fmt.Errorf("store: read secret metadata: %w", err)
	}
	m.HasPassphrase = hasPass == 1
	m.RetrievalStep = step == 1
	m.Deletable = del == 1
	m.ExpiresAt = fromUnix(expires)
	m.CreatedAt = fromUnix(created)
	m.AttemptsLeft = maxFailed - failed
	if !m.ExpiresAt.IsZero() && !m.ExpiresAt.After(s.Now()) {
		return Meta{}, ErrNotFound
	}
	if m.ViewsRemaining <= 0 {
		return Meta{}, ErrNotFound
	}
	return m, nil
}

// Reveal is the result of a successful consumption.
type Reveal struct {
	Kind           string
	Ciphertext     []byte
	StorageRef     string
	SizeBytes      int64
	ViewsRemaining int
	Destroyed      bool
}

// Consume verifies the read token, decrements the view counter and returns the
// ciphertext, all in one transaction.
//
// Everything about this function is deliberate:
//
//   - the read token is checked in constant time against the stored hash, and a
//     mismatch consumes no view: a preview bot or a wrong passphrase costs the
//     recipient nothing;
//   - the decrement is a conditional UPDATE guarded by views_remaining > 0, and
//     a row count of one is the proof that this caller won the race. Fifty
//     concurrent readers of a one-view secret therefore produce exactly one
//     success, on one node or several;
//   - when the last view is consumed the row is deleted inside the same
//     transaction, so the ciphertext is really gone, not just flagged.
func (s *Store) Consume(ctx context.Context, id string, readTokenHash []byte, now time.Time) (Reveal, error) {
	if !pcrypto.ValidID(id) {
		return Reveal{}, ErrNotFound
	}
	var out Reveal
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var (
			storedHash []byte
			ciphertext []byte
			storageRef sql.NullString
			kind       string
			size       int64
			remaining  int
			viewsMax   int
			expires    int64
			orgID      string
			creator    sql.NullString
			createdAt  int64
			groupID    sql.NullString
		)
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT read_token_hash, ciphertext, storage_ref, kind,
			size_bytes, views_remaining, views_max, expires_at, org_id, creator_id, created_at, group_id
			FROM secrets WHERE id = ?`), id).Scan(
			&storedHash, &ciphertext, &storageRef, &kind,
			&size, &remaining, &viewsMax, &expires, &orgID, &creator, &createdAt, &groupID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		if !pcrypto.EqualHash(storedHash, readTokenHash) {
			return ErrBadToken
		}
		if expires != 0 && !fromUnix(expires).After(now) {
			return ErrNotFound
		}

		res, err := tx.ExecContext(ctx, s.rebind(`UPDATE secrets
			SET views_remaining = views_remaining - 1, last_viewed_at = ?
			WHERE id = ? AND views_remaining > 0 AND (expires_at = 0 OR expires_at > ?)`),
			unix(now), id, unix(now))
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			// Another request took the last view first.
			return ErrExhausted
		}

		out = Reveal{
			Kind:           kind,
			Ciphertext:     ciphertext,
			StorageRef:     storageRef.String,
			SizeBytes:      size,
			ViewsRemaining: remaining - 1,
		}
		if out.ViewsRemaining <= 0 {
			if err := deleteSecretTx(ctx, s, tx, id, orgID, creator, groupID,
				StatusViewed, viewsMax, viewsMax, createdAt, now); err != nil {
				return err
			}
			out.Destroyed = true
		}
		return nil
	})
	if err != nil {
		return Reveal{}, err
	}
	return out, nil
}

// RegisterFailedAttempt records a wrong read token. When the limit is reached
// the secret is burned, which is the point: an attacker guessing a passphrase
// destroys the secret instead of eventually opening it.
func (s *Store) RegisterFailedAttempt(ctx context.Context, id string, now time.Time) (attemptsLeft int, burned bool, err error) {
	if !pcrypto.ValidID(id) {
		return 0, false, ErrNotFound
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var (
			failed, maxFailed, viewsMax, remaining int
			orgID                                  string
			creator, groupID                       sql.NullString
			createdAt                              int64
		)
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT failed_attempts, max_failed_attempts, views_max,
			views_remaining, org_id, creator_id, created_at, group_id FROM secrets WHERE id = ?`), id).Scan(
			&failed, &maxFailed, &viewsMax, &remaining, &orgID, &creator, &createdAt, &groupID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		failed++
		if failed >= maxFailed {
			if err := deleteSecretTx(ctx, s, tx, id, orgID, creator, groupID,
				StatusLocked, viewsMax-remaining, viewsMax, createdAt, now); err != nil {
				return err
			}
			attemptsLeft, burned = 0, true
			return nil
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE secrets SET failed_attempts = ? WHERE id = ?`), failed, id); err != nil {
			return err
		}
		attemptsLeft = maxFailed - failed
		return nil
	})
	return attemptsLeft, burned, err
}

// ReceiptStatus returns the sender view of a secret, verifying the receipt
// token against the live row or the tombstone.
func (s *Store) ReceiptStatus(ctx context.Context, id string, receiptTokenHash []byte) (Receipt, error) {
	if !pcrypto.ValidID(id) {
		return Receipt{}, ErrNotFound
	}
	var (
		r          Receipt
		storedHash []byte
		hasPass    int
		expires    int64
		created    int64
		lastViewed sql.NullInt64
	)
	err := s.queryRow(ctx, `SELECT receipt_token_hash, kind, has_passphrase, views_remaining, views_max,
		created_at, expires_at, last_viewed_at FROM secrets WHERE id = ?`, id).Scan(
		&storedHash, &r.Kind, &hasPass, &r.ViewsRemaining, &r.ViewsMax, &created, &expires, &lastViewed)
	switch {
	case err == nil:
		if !pcrypto.EqualHash(storedHash, receiptTokenHash) {
			return Receipt{}, ErrBadToken
		}
		r.ID = id
		r.HasPassphrase = hasPass == 1
		r.ViewsUsed = r.ViewsMax - r.ViewsRemaining
		r.CreatedAt = fromUnix(created)
		r.ExpiresAt = fromUnix(expires)
		if lastViewed.Valid {
			r.LastViewedAt = fromUnix(lastViewed.Int64)
		}
		r.Status = StatusActive
		if !r.ExpiresAt.IsZero() && !r.ExpiresAt.After(s.Now()) {
			r.Status = StatusExpired
		}
		return r, nil
	case errors.Is(err, sql.ErrNoRows):
		// Fall through to the tombstone.
	default:
		return Receipt{}, fmt.Errorf("store: read receipt: %w", err)
	}

	var closed int64
	err = s.queryRow(ctx, `SELECT receipt_token_hash, status, views_used, views_max, created_at, closed_at
		FROM secret_tombstones WHERE id = ?`, id).Scan(
		&storedHash, &r.Status, &r.ViewsUsed, &r.ViewsMax, &created, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrNotFound
	}
	if err != nil {
		return Receipt{}, fmt.Errorf("store: read tombstone: %w", err)
	}
	if !pcrypto.EqualHash(storedHash, receiptTokenHash) {
		return Receipt{}, ErrBadToken
	}
	r.ID = id
	r.CreatedAt = fromUnix(created)
	r.LastViewedAt = fromUnix(closed)
	return r, nil
}

// Burn destroys a secret on the sender's request.
func (s *Store) Burn(ctx context.Context, id string, receiptTokenHash []byte, now time.Time) error {
	return s.destroy(ctx, id, receiptTokenHash, false, StatusBurned, now)
}

// DeleteByRecipient destroys a secret on the recipient's request, if allowed.
func (s *Store) DeleteByRecipient(ctx context.Context, id string, readTokenHash []byte, now time.Time) error {
	return s.destroy(ctx, id, readTokenHash, true, StatusDeleted, now)
}

func (s *Store) destroy(ctx context.Context, id string, tokenHash []byte, byRecipient bool, status string, now time.Time) error {
	if !pcrypto.ValidID(id) {
		return ErrNotFound
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var (
			receiptHash, readHash []byte
			viewsMax, remaining   int
			deletable             int
			orgID                 string
			creator, groupID      sql.NullString
			createdAt             int64
		)
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT receipt_token_hash, read_token_hash, views_max,
			views_remaining, deletable_by_recipient, org_id, creator_id, created_at, group_id
			FROM secrets WHERE id = ?`), id).Scan(
			&receiptHash, &readHash, &viewsMax, &remaining, &deletable, &orgID, &creator, &createdAt, &groupID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		expected := receiptHash
		if byRecipient {
			if deletable != 1 {
				return ErrNotFound
			}
			expected = readHash
		}
		if !pcrypto.EqualHash(expected, tokenHash) {
			return ErrBadToken
		}
		return deleteSecretTx(ctx, s, tx, id, orgID, creator, groupID, status,
			viewsMax-remaining, viewsMax, createdAt, now)
	})
}

// PurgeExpired deletes every secret past its expiry and returns how many went.
// It runs every minute, so an expired ciphertext never lingers on disk.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.query(ctx, `SELECT id, org_id, creator_id, group_id, views_max, views_remaining, created_at
		FROM secrets WHERE (expires_at != 0 AND expires_at <= ?) OR views_remaining <= 0 LIMIT 500`, unix(now))
	if err != nil {
		return 0, fmt.Errorf("store: scan expired secrets: %w", err)
	}
	type doomed struct {
		id        string
		orgID     string
		creator   sql.NullString
		groupID   sql.NullString
		viewsMax  int
		remaining int
		createdAt int64
	}
	var list []doomed
	for rows.Next() {
		var d doomed
		if err := rows.Scan(&d.id, &d.orgID, &d.creator, &d.groupID, &d.viewsMax, &d.remaining, &d.createdAt); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // closed before the writes: a defer would hold the cursor open
			return 0, err
		}
		list = append(list, d)
	}
	_ = rows.Close() //nolint:sqlclosecheck // closed before the writes: a defer would hold the cursor open
	if err := rows.Err(); err != nil {
		return 0, err
	}

	purged := 0
	for _, d := range list {
		status := StatusExpired
		if d.remaining <= 0 {
			status = StatusViewed
		}
		err := s.tx(ctx, func(tx *sql.Tx) error {
			return deleteSecretTx(ctx, s, tx, d.id, d.orgID, d.creator, d.groupID, status,
				d.viewsMax-d.remaining, d.viewsMax, d.createdAt, now)
		})
		if err != nil {
			return purged, err
		}
		purged++
	}
	return purged, nil
}

// CountActive returns the number of live secrets, for the dashboard and doctor.
func (s *Store) CountActive(ctx context.Context) (int, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM secrets`).Scan(&n)
	return n, err
}

// deleteSecretTx writes the tombstone, then removes the row. Called from
// inside a transaction so that "gone" is never partial: either the ciphertext
// is deleted and the sender can still see what happened, or nothing changed.
func deleteSecretTx(ctx context.Context, s *Store, tx *sql.Tx, id, orgID string,
	creator, groupID sql.NullString, status string, viewsUsed, viewsMax int, createdAt int64, now time.Time) error {
	var receiptHash []byte
	err := tx.QueryRowContext(ctx, s.rebind(`SELECT receipt_token_hash FROM secrets WHERE id = ?`), id).Scan(&receiptHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO secret_tombstones
		(id, org_id, creator_id, receipt_token_hash, status, views_used, views_max, group_id, created_at, closed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		id, orgID, creator, receiptHash, status, viewsUsed, viewsMax, groupID, createdAt, unix(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM secrets WHERE id = ?`), id); err != nil {
		return err
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sub := range []string{"UNIQUE constraint failed", "duplicate key value", "SQLITE_CONSTRAINT"} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}
