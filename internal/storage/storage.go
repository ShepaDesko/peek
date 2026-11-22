// Package storage keeps encrypted file blobs. Every byte that reaches a
// backend is already sealed by the browser: a backend never sees a key, a file
// name or a MIME type, only an opaque object and its length.
//
// Two backends ship: the local filesystem (the default, and a shared NFS mount
// in HA) and anything S3-compatible. The interface is deliberately small —
// put, open, size, delete, list — because that is all a secret's lifecycle
// needs, and because a small interface is one that a third backend can satisfy
// without surprises.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/ShepaDesko/peek/internal/config"
)

// ErrNotFound is returned when an object is absent. Callers map it to the same
// "nothing here" answer as an expired secret: a recipient must not be able to
// tell an expired secret from one that never existed.
var ErrNotFound = errors.New("peek/storage: object not found")

// ErrTooLarge is returned when a stream exceeds the length it announced.
var ErrTooLarge = errors.New("peek/storage: object larger than announced")

// Backend stores opaque blobs under caller-chosen keys.
type Backend interface {
	// Put stores exactly size bytes read from r. A short or long stream is an
	// error and leaves nothing behind: a half-written blob would decrypt as a
	// truncated file, which the chunked format rejects anyway, but there is no
	// reason to keep it.
	Put(ctx context.Context, key string, size int64, r io.Reader) error
	// Open returns the object for reading. The caller closes it.
	Open(ctx context.Context, key string) (io.ReadCloser, int64, error)
	// Size reports the stored length without opening the object.
	Size(ctx context.Context, key string) (int64, error)
	// Delete removes an object. Deleting what is not there is not an error:
	// purge runs repeatedly and must stay idempotent.
	Delete(ctx context.Context, key string) error
	// List returns every stored key. The purge uses it to find orphans, so it
	// must enumerate everything, not a page.
	List(ctx context.Context) ([]string, error)
	// Describe is what `peek doctor` prints. It never contains a credential.
	Describe() string
}

// keyPattern is what a blob key may look like: base64url identifiers only.
// Keys come from crypto.NewID, but the storage layer checks anyway — a path
// traversal in a storage key would be a file write outside the data directory.
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// ValidKey reports whether key is acceptable to every backend.
func ValidKey(key string) bool { return keyPattern.MatchString(key) }

func checkKey(key string) error {
	if !ValidKey(key) {
		return fmt.Errorf("peek/storage: invalid object key")
	}
	return nil
}

// Open builds the backend named by the configuration.
func Open(cfg config.Storage) (Backend, error) {
	switch cfg.Backend {
	case "local", "":
		return NewLocal(cfg.Path)
	case "s3":
		return NewS3(cfg)
	default:
		return nil, fmt.Errorf("peek/storage: unknown backend %q", cfg.Backend)
	}
}

// limitedReader reads at most n+1 bytes so a stream that overruns its
// announced length is caught rather than silently truncated.
type limitedReader struct {
	r    io.Reader
	left int64
	over bool
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		// One extra read to find out whether more was coming.
		var probe [1]byte
		n, err := l.r.Read(probe[:])
		if n > 0 {
			l.over = true
			return 0, ErrTooLarge
		}
		if err == nil {
			err = io.EOF
		}
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, err
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
