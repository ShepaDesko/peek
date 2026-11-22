package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
)

// A file lives through three states:
//
//  1. pending — uploaded, not yet claimed by a secret, short expiry. If the
//     sender closes the tab before creating the secret, the purge collects it.
//  2. attached — claimed by a bundle, expiry aligned with the secrets that
//     reference it.
//  3. granted — a recipient revealed and holds a download grant, so the expiry
//     is pushed forward far enough for the download to finish even though the
//     secret row itself may already be gone.
//
// Nothing here ever sees a file name, a MIME type or a key.

// PendingFile is an accepted upload, before any secret claims it.
type PendingFile struct {
	ID             string
	OrgID          string
	CreatorID      string
	ClaimTokenHash []byte
	SizeBytes      int64
	ExpiresAt      time.Time
}

// FileRow is one blob as the server knows it.
type FileRow struct {
	ID        string
	SizeBytes int64
	CreatedAt time.Time
}

// ErrNotClaimable is returned when a blob cannot be attached: wrong token,
// already attached, expired, or belonging to another organisation.
var ErrNotClaimable = errors.New("store: file cannot be attached to this secret")

// CreatePendingFile records an upload that has already been written to storage.
func (s *Store) CreatePendingFile(ctx context.Context, p PendingFile) error {
	if !pcrypto.ValidID(p.ID) {
		return errors.New("store: malformed file id")
	}
	_, err := s.exec(ctx, `INSERT INTO secret_files
		(id, org_id, creator_id, bundle_id, claim_token_hash, size_bytes, created_at, expires_at)
		VALUES (?, ?, ?, NULL, ?, ?, ?, ?)`,
		p.ID, p.OrgID, nullString(p.CreatorID), p.ClaimTokenHash, p.SizeBytes,
		unix(s.Now()), unix(p.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("store: record upload: %w", err)
	}
	return nil
}

// FileClaim is one blob a secret wants to attach, with the token proving the
// claimant is the uploader.
type FileClaim struct {
	ID        string
	TokenHash []byte
}

// claimFilesTx attaches blobs to a bundle inside an existing transaction, so a
// secret and its files appear together or not at all.
//
// The conditional UPDATE is what makes the claim safe: a blob that is already
// attached, expired, from another organisation or claimed with the wrong token
// simply does not match, and the row count says so.
func claimFilesTx(ctx context.Context, s *Store, tx *sql.Tx, claims []FileClaim,
	orgID, bundleID string, expires, now time.Time) (int64, error) {
	var total int64
	for _, c := range claims {
		if !pcrypto.ValidID(c.ID) || len(c.TokenHash) != 32 {
			return 0, ErrNotClaimable
		}
		var size int64
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT size_bytes FROM secret_files
			WHERE id = ? AND org_id = ? AND bundle_id IS NULL AND expires_at > ? AND claim_token_hash = ?`),
			c.ID, orgID, unix(now), c.TokenHash).Scan(&size)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotClaimable
		}
		if err != nil {
			return 0, err
		}

		res, err := tx.ExecContext(ctx, s.rebind(`UPDATE secret_files
			SET bundle_id = ?, expires_at = ?
			WHERE id = ? AND bundle_id IS NULL AND claim_token_hash = ?`),
			bundleID, unix(expires), c.ID, c.TokenHash)
		if err != nil {
			return 0, err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if affected != 1 {
			// Someone else claimed it between the check and the update.
			return 0, ErrNotClaimable
		}
		total += size
	}
	return total, nil
}

// AttachFiles claims blobs for a bundle outside any other transaction. The
// secret creation path uses the transactional form instead.
func (s *Store) AttachFiles(ctx context.Context, claims []FileClaim, orgID, bundleID string, expires time.Time) (int64, error) {
	var total int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		total, err = claimFilesTx(ctx, s, tx, claims, orgID, bundleID, expires, s.Now())
		return err
	})
	return total, err
}

// BundleFiles lists the blobs attached to a bundle.
func (s *Store) BundleFiles(ctx context.Context, bundleID string) ([]FileRow, error) {
	rows, err := s.query(ctx, `SELECT id, size_bytes, created_at FROM secret_files
		WHERE bundle_id = ? ORDER BY created_at, id`, bundleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []FileRow
	for rows.Next() {
		var f FileRow
		var created int64
		if err := rows.Scan(&f.ID, &f.SizeBytes, &created); err != nil {
			return nil, err
		}
		f.CreatedAt = fromUnix(created)
		out = append(out, f)
	}
	return out, rows.Err()
}

// GrantDownloads records a short-lived permission to fetch a bundle's blobs,
// and pushes the blobs' expiry past the end of the grant so that a download
// started after the last view can still finish.
func (s *Store) GrantDownloads(ctx context.Context, tokenHash []byte, orgID, bundleID, secretID string, expires time.Time) error {
	if len(tokenHash) != 32 {
		return errors.New("store: malformed grant token")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO file_grants
			(token_hash, org_id, bundle_id, secret_id, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`),
			tokenHash, orgID, bundleID, secretID, unix(s.Now()), unix(expires)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.rebind(`UPDATE secret_files
			SET expires_at = ? WHERE bundle_id = ? AND expires_at < ?`),
			unix(expires), bundleID, unix(expires))
		return err
	})
}

// GrantedFile checks a download grant and returns the blob's size. A grant that
// does not exist, has expired, or names another bundle is reported exactly like
// a missing file: a recipient must not learn which of the two it was.
func (s *Store) GrantedFile(ctx context.Context, tokenHash []byte, fileID string, now time.Time) (FileRow, error) {
	if len(tokenHash) != 32 || !pcrypto.ValidID(fileID) {
		return FileRow{}, ErrNotFound
	}
	var (
		f       FileRow
		created int64
	)
	err := s.queryRow(ctx, `SELECT f.id, f.size_bytes, f.created_at
		FROM file_grants g JOIN secret_files f ON f.bundle_id = g.bundle_id
		WHERE g.token_hash = ? AND g.expires_at > ? AND f.id = ?`,
		tokenHash, unix(now), fileID).Scan(&f.ID, &f.SizeBytes, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return FileRow{}, ErrNotFound
	}
	if err != nil {
		return FileRow{}, err
	}
	f.CreatedAt = fromUnix(created)
	return f, nil
}

// PurgeFiles deletes the rows of blobs nothing references any more and returns
// their storage keys, which the caller removes from the backend.
//
// Two cases, and the difference matters:
//
//   - a blob nobody ever claimed goes when its upload window closes;
//   - an attached blob goes as soon as every secret of its bundle is gone and
//     no live grant remains — not when its own expiry says so. That is what
//     makes "the file really disappears on the last view, or when the sender
//     burns the secret" true to the minute rather than to the original expiry.
func (s *Store) PurgeFiles(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.query(ctx, `SELECT id FROM secret_files
		WHERE (bundle_id IS NULL AND expires_at <= ?)
		   OR (bundle_id IS NOT NULL
		       AND NOT EXISTS (SELECT 1 FROM secrets s WHERE s.bundle_id = secret_files.bundle_id)
		       AND NOT EXISTS (SELECT 1 FROM file_grants g
		                       WHERE g.bundle_id = secret_files.bundle_id AND g.expires_at > ?))
		LIMIT 500`, unix(now), unix(now))
	if err != nil {
		return nil, fmt.Errorf("store: scan expired files: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // closed before the writes
			return nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close() //nolint:sqlclosecheck // closed before the writes
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, id := range ids {
		if _, err := s.exec(ctx, `DELETE FROM secret_files WHERE id = ?`, id); err != nil {
			return nil, err
		}
	}
	if _, err := s.exec(ctx, `DELETE FROM file_grants WHERE expires_at <= ?`, unix(now)); err != nil {
		return ids, err
	}
	return ids, nil
}

// KnownFileIDs returns every blob the database knows about, so the purge can
// spot storage objects no row points at — the orphans a crash leaves behind.
func (s *Store) KnownFileIDs(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.query(ctx, `SELECT id FROM secret_files`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := map[string]struct{}{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// CountFiles returns how many blobs are stored and their total size, for the
// dashboard and `peek doctor`.
func (s *Store) CountFiles(ctx context.Context) (count int, bytes int64, err error) {
	var total sql.NullInt64
	err = s.queryRow(ctx, `SELECT COUNT(*), SUM(size_bytes) FROM secret_files`).Scan(&count, &total)
	return count, total.Int64, err
}
