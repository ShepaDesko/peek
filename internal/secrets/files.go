package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/storage"
	"github.com/ShepaDesko/peek/internal/store"
)

// Attachments are deliberately boring on the server: a blob arrives already
// encrypted, is written to storage under an opaque id, and is handed back only
// to someone who has proved possession of a read token. The server never sees
// a file name, a MIME type or a key — those are inside the sealed payload.
//
// The upload happens before the secret exists, because the browser needs the
// blob ids to put in that payload. A pending blob therefore belongs to nobody
// for a short while, which is why it carries a claim token: whoever uploaded
// it is the only one who can attach it to a secret.

// ErrNoStorage is returned when a file operation is attempted on an instance
// with no storage backend configured.
var ErrNoStorage = errors.New("secrets: no file storage configured")

// ErrTooLarge is returned when an upload exceeds the instance policy.
var ErrTooLarge = errors.New("secrets: file larger than the instance allows")

// SetStorage attaches the blob backend. Without it, file secrets are refused
// rather than silently degraded.
func (s *Service) SetStorage(b storage.Backend) { s.storage = b }

// Storage returns the configured backend, or nil.
func (s *Service) Storage() storage.Backend { return s.storage }

// Upload is the result of accepting one encrypted blob.
type Upload struct {
	ID string `json:"id"`
	// Token is what the creation request must present to attach this blob.
	// It is generated here, handed to the uploader once, and stored hashed.
	Token     string    `json:"token"`
	Size      int64     `json:"size"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MaxUploadBytes is the largest encrypted stream the instance accepts. It is
// the policy's plaintext limit plus the chunked format's own overhead, so an
// operator who writes "100 MiB" gets a 100 MiB file through rather than a
// confusing refusal a few kilobytes short.
func (s *Service) MaxUploadBytes() int64 {
	plain := s.cfg.Policy.MaxFileBytes
	if plain <= 0 {
		return 0
	}
	return pcrypto.EncryptedFileSize(plain, pcrypto.DefaultChunkSize)
}

// AcceptUpload streams an encrypted blob into storage and records it as
// pending. size must be the exact stream length; a short or long body is
// refused and nothing is kept.
func (s *Service) AcceptUpload(ctx context.Context, orgID, creatorID string, size int64, body io.Reader) (Upload, error) {
	if s.storage == nil {
		return Upload{}, ErrNoStorage
	}
	if !allowedKind(s.cfg.Policy.AllowedKinds, pcrypto.KindFile) {
		return Upload{}, &PolicyError{Field: "kind", Reason: "this instance does not allow file secrets"}
	}
	if size < 0 {
		return Upload{}, &PolicyError{Field: "size", Reason: "unknown upload length"}
	}
	if max := s.MaxUploadBytes(); max > 0 && size > max {
		return Upload{}, ErrTooLarge
	}
	// Smaller than a header plus one tag cannot be a Peek file stream. This is
	// a sanity check, not a security one: the recipient's browser is what
	// actually authenticates the bytes.
	if size < int64(pcrypto.FileHeaderLen+pcrypto.TagLen) {
		return Upload{}, &PolicyError{Field: "size", Reason: "not an encrypted file stream"}
	}

	id, err := pcrypto.NewID()
	if err != nil {
		return Upload{}, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Upload{}, err
	}

	if err := s.storage.Put(ctx, id, size, body); err != nil {
		return Upload{}, err
	}

	window := s.cfg.Policy.UploadWindow.Std()
	if window <= 0 {
		window = 2 * time.Hour
	}
	expires := s.now().Add(window)

	err = s.store.CreatePendingFile(ctx, store.PendingFile{
		ID:             id,
		OrgID:          orgID,
		CreatorID:      creatorID,
		ClaimTokenHash: pcrypto.HashReadToken(token),
		SizeBytes:      size,
		ExpiresAt:      expires,
	})
	if err != nil {
		// The row is what makes the blob reachable; without it the blob is
		// unreferenced, so remove it now rather than wait for the orphan pass.
		if derr := s.storage.Delete(ctx, id); derr != nil {
			return Upload{}, fmt.Errorf("%w (and the orphan blob could not be removed: %w)", err, derr)
		}
		return Upload{}, err
	}

	return Upload{
		ID:        id,
		Token:     pcrypto.B64.EncodeToString(token),
		Size:      size,
		ExpiresAt: expires,
	}, nil
}

// GrantDownloads issues the short-lived permission a recipient needs to fetch
// the blobs of a bundle after a successful reveal. It returns the token in the
// clear once; only its hash is stored.
//
// This exists because the secret row is deleted the moment the last view is
// consumed. Without a grant, a one-view secret with a 100 MiB attachment would
// become unreadable at the instant it became readable.
func (s *Service) GrantDownloads(ctx context.Context, orgID, bundleID, secretID string) (string, time.Time, error) {
	if bundleID == "" {
		return "", time.Time{}, nil
	}
	files, err := s.store.BundleFiles(ctx, bundleID)
	if err != nil {
		return "", time.Time{}, err
	}
	if len(files) == 0 {
		return "", time.Time{}, nil
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", time.Time{}, err
	}
	window := s.cfg.Policy.DownloadWindow.Std()
	if window <= 0 {
		window = 30 * time.Minute
	}
	expires := s.now().Add(window)
	if err := s.store.GrantDownloads(ctx, pcrypto.HashReadToken(token), orgID, bundleID, secretID, expires); err != nil {
		return "", time.Time{}, err
	}
	return pcrypto.B64.EncodeToString(token), expires, nil
}

// OpenDownload checks a grant and returns the blob. Everything that can go
// wrong — unknown grant, expired grant, file from another bundle, file already
// purged — is reported as ErrNotFound: a recipient must not be able to probe
// which it was.
func (s *Service) OpenDownload(ctx context.Context, grantToken []byte, fileID string) (io.ReadCloser, int64, error) {
	if s.storage == nil {
		return nil, 0, ErrNoStorage
	}
	if len(grantToken) != 32 {
		return nil, 0, ErrNotFound
	}
	row, err := s.store.GrantedFile(ctx, pcrypto.HashReadToken(grantToken), fileID, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	rc, size, err := s.storage.Open(ctx, row.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	if size <= 0 {
		size = row.SizeBytes
	}
	return rc, size, nil
}

// BundleFiles lists the blobs of a bundle, for the receipt page.
func (s *Service) BundleFiles(ctx context.Context, bundleID string) ([]store.FileRow, error) {
	return s.store.BundleFiles(ctx, bundleID)
}

// PurgeFiles drops the rows and blobs nothing references any more, then the
// storage objects no row points at. Both halves matter: a crash between the
// write and the insert leaves an object with no row, and that is what the
// second half collects.
func (s *Service) PurgeFiles(ctx context.Context) (rows int, orphans int, err error) {
	ids, err := s.store.PurgeFiles(ctx, s.now())
	if err != nil {
		return 0, 0, err
	}
	if s.storage == nil {
		return len(ids), 0, nil
	}
	for _, id := range ids {
		if derr := s.storage.Delete(ctx, id); derr != nil && err == nil {
			err = derr
		}
	}
	if err != nil {
		return len(ids), 0, err
	}

	orphans, err = s.purgeOrphans(ctx)
	return len(ids), orphans, err
}

// purgeOrphans removes storage objects the database does not know about. An
// object younger than the upload window is left alone: it may belong to an
// upload that is still in flight.
func (s *Service) purgeOrphans(ctx context.Context) (int, error) {
	keys, err := s.storage.List(ctx)
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}
	known, err := s.store.KnownFileIDs(ctx)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, k := range keys {
		if _, ok := known[k]; ok {
			continue
		}
		if err := s.storage.Delete(ctx, k); err != nil {
			return removed, err
		}
		removed++
	}

	// A crashed upload also leaves a temporary file on the local backend.
	if local, ok := s.storage.(*storage.Local); ok {
		window := int64(s.cfg.Policy.UploadWindow.Std().Seconds())
		if window <= 0 {
			window = int64((2 * time.Hour).Seconds())
		}
		n, err := local.CleanTemporaries(window)
		if err != nil {
			return removed, err
		}
		removed += n
	}
	return removed, nil
}
