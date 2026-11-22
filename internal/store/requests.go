package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

// Secret requests turn the usual direction around: the person asking is the
// one who must be able to read, and the person answering must not be able to
// read back what they deposited.
//
// The requester's private key never reaches the server. What is stored is the
// public half — so a deposit can be sealed to it — the prompt sealed with the
// request key from the deposit link's fragment, and a hash of the read token
// derived from that same key, which is what stops anyone enumerating requests.

// ErrRequestClosed is returned when a request has reached its deposit limit or
// expired. Callers map it to the same answer as "no such request".
var ErrRequestClosed = errors.New("store: request closed")

// NewRequest is a secret request as the browser submits it.
type NewRequest struct {
	ID               string
	OrgID            string
	CreatorID        string
	PublicKey        []byte
	ReadTokenHash    []byte
	ReceiptTokenHash []byte
	PromptEnc        []byte
	KDF              pcrypto.KDFParams
	LabelEnc         []byte
	NotifyEmailEnc   []byte
	NotifyOnDeposit  bool
	MaxDeposits      int
	ExpiresAt        time.Time
}

// RequestMeta is what a depositor may see before proving possession of the key.
type RequestMeta struct {
	ID                string
	KDF               pcrypto.KDFParams
	DepositsRemaining int
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

// RequestOpened is the prompt, released once the depositor proves they hold
// the request key from the link.
type RequestOpened struct {
	ID        string
	PromptEnc []byte
	ExpiresAt time.Time
}

// Deposit is one answer to a request, as the requester sees it on their
// receipt page. The wrapped key is useless without the private key, which
// never left their own link.
type Deposit struct {
	SecretID       string
	WrappedKey     []byte
	KDF            pcrypto.KDFParams
	HasPassphrase  bool
	SizeBytes      int64
	CreatedAt      time.Time
	ViewsRemaining int
}

// RequestReceipt is the requester's view of their own request.
type RequestReceipt struct {
	ID                string
	LabelEnc          []byte
	MaxDeposits       int
	DepositsUsed      int
	CreatedAt         time.Time
	ExpiresAt         time.Time
	Deposits          []Deposit
	DepositsRemaining int
}

// CreateRequest stores a new secret request.
func (s *Store) CreateRequest(ctx context.Context, n NewRequest) error {
	if !pcrypto.ValidID(n.ID) {
		return errors.New("store: malformed request id")
	}
	if len(n.ReadTokenHash) != 32 || len(n.ReceiptTokenHash) != 32 {
		return errors.New("store: malformed request tokens")
	}
	if !pcrypto.ValidRequestPublicKey(n.PublicKey) {
		// A point that is not on the curve would be an attack on the
		// depositor's own key exchange, so it is refused on the way in.
		return errors.New("store: malformed request public key")
	}
	max := n.MaxDeposits
	if max < 1 {
		max = 1
	}
	_, err := s.exec(ctx, `INSERT INTO secret_requests
		(id, org_id, creator_id, public_key, read_token_hash, receipt_token_hash, prompt_enc,
		 kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism,
		 label_enc, notify_email_enc, notify_on_deposit, max_deposits, deposits_used,
		 created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		n.ID, n.OrgID, nullString(n.CreatorID), n.PublicKey, n.ReadTokenHash, n.ReceiptTokenHash, n.PromptEnc,
		n.KDF.Salt, n.KDF.MemoryKiB, n.KDF.Iterations, n.KDF.Parallelism,
		n.LabelEnc, n.NotifyEmailEnc, boolToInt(n.NotifyOnDeposit), max,
		unix(s.Now()), unix(n.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: create request: %w", err)
	}
	return nil
}

// RequestMetaByID returns the public metadata of a live request. A closed,
// expired or absent request is reported as not found, all three alike.
func (s *Store) RequestMetaByID(ctx context.Context, id string) (RequestMeta, error) {
	if !pcrypto.ValidID(id) {
		return RequestMeta{}, ErrNotFound
	}
	var (
		m            RequestMeta
		expires      int64
		created      int64
		maxDep, used int
	)
	err := s.queryRow(ctx, `SELECT id, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism,
		max_deposits, deposits_used, created_at, expires_at FROM secret_requests WHERE id = ?`, id).Scan(
		&m.ID, &m.KDF.Salt, &m.KDF.MemoryKiB, &m.KDF.Iterations, &m.KDF.Parallelism,
		&maxDep, &used, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestMeta{}, ErrNotFound
	}
	if err != nil {
		return RequestMeta{}, err
	}
	if used >= maxDep || (expires != 0 && !fromUnix(expires).After(s.Now())) {
		return RequestMeta{}, ErrNotFound
	}
	m.DepositsRemaining = maxDep - used
	m.CreatedAt = fromUnix(created)
	m.ExpiresAt = fromUnix(expires)
	return m, nil
}

// OpenRequest releases the prompt to whoever proves possession of the request
// key. The public key is deliberately not returned: the browser takes it from
// the link's fragment, so a compromised server cannot substitute its own and
// read the deposits.
func (s *Store) OpenRequest(ctx context.Context, id string, readTokenHash []byte, now time.Time) (RequestOpened, error) {
	if !pcrypto.ValidID(id) || len(readTokenHash) != 32 {
		return RequestOpened{}, ErrNotFound
	}
	var (
		out          RequestOpened
		storedHash   []byte
		expires      int64
		maxDep, used int
	)
	err := s.queryRow(ctx, `SELECT read_token_hash, prompt_enc, max_deposits, deposits_used, expires_at
		FROM secret_requests WHERE id = ?`, id).Scan(&storedHash, &out.PromptEnc, &maxDep, &used, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestOpened{}, ErrNotFound
	}
	if err != nil {
		return RequestOpened{}, err
	}
	if !pcrypto.EqualHash(storedHash, readTokenHash) {
		return RequestOpened{}, ErrBadToken
	}
	if used >= maxDep || (expires != 0 && !fromUnix(expires).After(now)) {
		return RequestOpened{}, ErrNotFound
	}
	out.ID = id
	out.ExpiresAt = fromUnix(expires)
	return out, nil
}

// DepositTarget is what a deposit needs from the request it answers.
type DepositTarget struct {
	OrgID           string
	NotifyEmailEnc  []byte
	NotifyOnDeposit bool
}

// Deposit stores an answer to a request and counts it, in one transaction.
//
// The counter is incremented with a conditional UPDATE guarded by
// deposits_used < max_deposits, so concurrent depositors on a single-use
// request produce exactly one success, here and on PostgreSQL alike.
func (s *Store) Deposit(ctx context.Context, requestID string, readTokenHash []byte,
	secret NewSecret, claims []FileClaim, now time.Time) (DepositTarget, error) {
	if !pcrypto.ValidID(requestID) || len(readTokenHash) != 32 {
		return DepositTarget{}, ErrNotFound
	}
	var target DepositTarget
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var (
			storedHash   []byte
			orgID        string
			expires      int64
			maxDep, used int
			notifyEnc    []byte
			notifyOn     int
		)
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT read_token_hash, org_id, max_deposits,
			deposits_used, expires_at, notify_email_enc, notify_on_deposit
			FROM secret_requests WHERE id = ?`), requestID).Scan(
			&storedHash, &orgID, &maxDep, &used, &expires, &notifyEnc, &notifyOn)
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

		res, err := tx.ExecContext(ctx, s.rebind(`UPDATE secret_requests
			SET deposits_used = deposits_used + 1
			WHERE id = ? AND deposits_used < max_deposits AND (expires_at = 0 OR expires_at > ?)`),
			requestID, unix(now))
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return ErrRequestClosed
		}

		secret.OrgID = orgID
		secret.RequestID = requestID
		if secret.BundleID == "" {
			secret.BundleID = secret.ID
		}
		if err := insertSecretTx(ctx, s, tx, secret); err != nil {
			return err
		}
		if len(claims) > 0 {
			if _, err := claimFilesTx(ctx, s, tx, claims, orgID, secret.BundleID, secret.ExpiresAt, now); err != nil {
				return err
			}
		}

		target = DepositTarget{OrgID: orgID, NotifyOnDeposit: notifyOn == 1}
		if notifyOn == 1 {
			target.NotifyEmailEnc = notifyEnc
		}
		return nil
	})
	return target, err
}

// RequestReceiptStatus returns the requester's own view, deposits included.
func (s *Store) RequestReceiptStatus(ctx context.Context, id string, receiptTokenHash []byte) (RequestReceipt, error) {
	if !pcrypto.ValidID(id) || len(receiptTokenHash) != 32 {
		return RequestReceipt{}, ErrNotFound
	}
	var (
		r          RequestReceipt
		storedHash []byte
		created    int64
		expires    int64
	)
	err := s.queryRow(ctx, `SELECT receipt_token_hash, label_enc, max_deposits, deposits_used,
		created_at, expires_at FROM secret_requests WHERE id = ?`, id).Scan(
		&storedHash, &r.LabelEnc, &r.MaxDeposits, &r.DepositsUsed, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestReceipt{}, ErrNotFound
	}
	if err != nil {
		return RequestReceipt{}, err
	}
	if !pcrypto.EqualHash(storedHash, receiptTokenHash) {
		return RequestReceipt{}, ErrBadToken
	}
	r.ID = id
	r.CreatedAt = fromUnix(created)
	r.ExpiresAt = fromUnix(expires)
	r.DepositsRemaining = r.MaxDeposits - r.DepositsUsed

	rows, err := s.query(ctx, `SELECT id, wrapped_key, kdf_salt, kdf_memory_kib, kdf_iterations,
		kdf_parallelism, has_passphrase, size_bytes, created_at, views_remaining
		FROM secrets WHERE request_id = ? ORDER BY created_at, id`, id)
	if err != nil {
		return RequestReceipt{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			d       Deposit
			hasPass int
			at      int64
		)
		if err := rows.Scan(&d.SecretID, &d.WrappedKey, &d.KDF.Salt, &d.KDF.MemoryKiB,
			&d.KDF.Iterations, &d.KDF.Parallelism, &hasPass, &d.SizeBytes, &at, &d.ViewsRemaining); err != nil {
			return RequestReceipt{}, err
		}
		d.HasPassphrase = hasPass == 1
		d.CreatedAt = fromUnix(at)
		r.Deposits = append(r.Deposits, d)
	}
	return r, rows.Err()
}

// CloseRequest destroys a request on its owner's demand. Deposits already made
// keep their own lifecycle: destroying the request must not destroy a secret
// the requester has not read yet.
func (s *Store) CloseRequest(ctx context.Context, id string, receiptTokenHash []byte) error {
	if !pcrypto.ValidID(id) || len(receiptTokenHash) != 32 {
		return ErrNotFound
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var storedHash []byte
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT receipt_token_hash FROM secret_requests WHERE id = ?`), id).
			Scan(&storedHash)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !pcrypto.EqualHash(storedHash, receiptTokenHash) {
			return ErrBadToken
		}
		_, err = tx.ExecContext(ctx, s.rebind(`DELETE FROM secret_requests WHERE id = ?`), id)
		return err
	})
}

// PurgeRequests removes requests that expired or filled up. A request is only
// collected once every deposit it received has been read or purged, so closing
// the request never takes an unread deposit with it.
func (s *Store) PurgeRequests(ctx context.Context, now time.Time) (int, error) {
	res, err := s.exec(ctx, `DELETE FROM secret_requests
		WHERE ((expires_at != 0 AND expires_at <= ?) OR deposits_used >= max_deposits)
		  AND NOT EXISTS (SELECT 1 FROM secrets WHERE secrets.request_id = secret_requests.id)`,
		unix(now))
	if err != nil {
		return 0, fmt.Errorf("store: purge requests: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// CountRequests returns how many requests are open, for the dashboard.
func (s *Store) CountRequests(ctx context.Context, creatorID string) (int, error) {
	var n int
	var err error
	if creatorID == "" {
		err = s.queryRow(ctx, `SELECT COUNT(*) FROM secret_requests`).Scan(&n)
	} else {
		err = s.queryRow(ctx, `SELECT COUNT(*) FROM secret_requests WHERE creator_id = ?`, creatorID).Scan(&n)
	}
	return n, err
}

// ListRequests returns a user's open requests for the dashboard.
func (s *Store) ListRequests(ctx context.Context, creatorID string, limit int) ([]RequestReceipt, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.query(ctx, `SELECT r.id, r.label_enc, r.max_deposits, r.deposits_used,
		r.created_at, r.expires_at FROM secret_requests r
		WHERE r.creator_id = ? ORDER BY r.created_at DESC LIMIT ?`, creatorID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []RequestReceipt
	for rows.Next() {
		var (
			r                RequestReceipt
			created, expires int64
		)
		if err := rows.Scan(&r.ID, &r.LabelEnc, &r.MaxDeposits, &r.DepositsUsed, &created, &expires); err != nil {
			return nil, err
		}
		r.CreatedAt = fromUnix(created)
		r.ExpiresAt = fromUnix(expires)
		r.DepositsRemaining = r.MaxDeposits - r.DepositsUsed
		out = append(out, r)
	}
	return out, rows.Err()
}
