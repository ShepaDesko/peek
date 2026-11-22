package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Local stores blobs as files under a single directory. It is the default, and
// in a high-availability setup that directory is a shared mount (NFS, or
// anything else every node sees): nothing here assumes a local disk beyond
// rename being atomic within the directory, which holds on NFSv4.
type Local struct {
	dir string
}

// NewLocal prepares the directory and returns the backend.
func NewLocal(dir string) (*Local, error) {
	if dir == "" {
		return nil, errors.New("peek/storage: storage.path cannot be empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// 0700: the blobs are already encrypted, but there is no reason for any
	// other account on the host to enumerate how many secrets exist.
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("peek/storage: cannot create %s: %w", abs, err)
	}
	return &Local{dir: abs}, nil
}

func (l *Local) path(key string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	return filepath.Join(l.dir, key), nil
}

// Put writes the blob to a temporary file in the same directory and renames it
// into place, so a crashed or disconnected upload never leaves a readable
// object under its final name.
func (l *Local) Put(ctx context.Context, key string, size int64, r io.Reader) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(l.dir, ".upload-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName) // no-op once the rename succeeded
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}

	limited := &limitedReader{r: r, left: size}
	written, err := io.Copy(tmp, limited)
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("peek/storage: expected %d bytes, got %d", size, written)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

func (l *Local) Open(_ context.Context, key string) (io.ReadCloser, int64, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p) //nolint:gosec // the key is validated above
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

func (l *Local) Size(_ context.Context, key string) (int64, error) {
	p, err := l.path(key)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return info.Size(), nil
}

func (l *Local) Delete(_ context.Context, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (l *Local) List(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !ValidKey(name) {
			continue
		}
		keys = append(keys, name)
	}
	return keys, nil
}

// Describe names the directory, which is not a secret and is exactly what an
// operator reading `peek doctor` needs.
func (l *Local) Describe() string { return "local directory " + l.dir }

// Dir is the resolved directory, for the setup command and the backup.
func (l *Local) Dir() string { return l.dir }

// CleanTemporaries removes upload temporaries left by a crash. The purge calls
// it so a dead process cannot slowly fill the data directory.
func (l *Local) CleanTemporaries(olderThanSeconds int64) (int, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), ".upload-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Now().Unix()-info.ModTime().Unix() < olderThanSeconds {
			continue
		}
		if err := os.Remove(filepath.Join(l.dir, e.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}
