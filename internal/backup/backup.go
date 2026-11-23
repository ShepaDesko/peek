// Package backup takes and restores consistent hot backups.
//
// A backup is a tar.gz holding the database snapshot, the configuration, the
// master key and the encrypted file blobs, optionally encrypted with age. It
// contains the ciphertext of every still-active secret, which is why
// docs/BACKUP.md insists on a short retention.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// Manifest describes a backup archive.
type Manifest struct {
	Version     int       `json:"version"`
	PeekVersion string    `json:"peek_version"`
	CreatedAt   time.Time `json:"created_at"`
	Driver      string    `json:"driver"`
	Encrypted   bool      `json:"encrypted"`
	Files       []string  `json:"files"`
	Hostname    string    `json:"hostname"`
}

// Options drive Create.
type Options struct {
	Config      *config.Config
	Dir         string
	Passphrase  string
	PeekVersion string
	Keep        int
}

// Result reports where the archive landed.
type Result struct {
	Path      string
	Bytes     int64
	Encrypted bool
	Pruned    []string
}

const manifestVersion = 1

// Create writes a new backup archive.
//
// The SQLite snapshot uses VACUUM INTO, which produces a consistent copy while
// the service keeps serving: no downtime, no partially written page.
func Create(ctx context.Context, opts Options) (*Result, error) {
	cfg := opts.Config
	if cfg == nil {
		return nil, errors.New("backup: missing configuration")
	}
	dir := opts.Dir
	if dir == "" {
		dir = cfg.Backup.Dir
	}
	if dir == "" {
		return nil, errors.New("backup: no destination directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("backup: create %s: %w", dir, err)
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	name := "peek-" + stamp + ".tar.gz"
	passphrase := opts.Passphrase
	if passphrase == "" {
		passphrase = cfg.Backup.Passphrase
	}
	if passphrase != "" {
		name += ".age"
	}
	path := filepath.Join(dir, name)

	staging, err := os.MkdirTemp("", "peek-backup-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(staging) }()

	manifest := Manifest{
		Version:     manifestVersion,
		PeekVersion: opts.PeekVersion,
		CreatedAt:   time.Now().UTC(),
		Driver:      cfg.Database.Driver,
		Encrypted:   passphrase != "",
	}
	manifest.Hostname, _ = os.Hostname()

	// 1. database snapshot
	switch cfg.Database.Driver {
	case "sqlite":
		snapshot := filepath.Join(staging, "peek.db")
		if err := snapshotSQLite(ctx, cfg, snapshot); err != nil {
			return nil, err
		}
		manifest.Files = append(manifest.Files, "peek.db")
	case "postgres":
		snapshot := filepath.Join(staging, "peek.dump")
		if err := snapshotPostgres(ctx, cfg, snapshot); err != nil {
			return nil, err
		}
		manifest.Files = append(manifest.Files, "peek.dump")
	}

	// 2. configuration and master key
	for _, item := range []struct{ src, dst string }{
		{configPathOf(cfg), "peek.toml"},
		{cfg.MasterKeyFile, "master.key"},
	} {
		if item.src == "" {
			continue
		}
		if err := copyFile(item.src, filepath.Join(staging, item.dst)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		manifest.Files = append(manifest.Files, item.dst)
	}

	// 3. encrypted file blobs
	if cfg.Storage.Backend == "local" && cfg.Storage.Path != "" {
		if _, err := os.Stat(cfg.Storage.Path); err == nil {
			if err := copyTree(cfg.Storage.Path, filepath.Join(staging, "files")); err != nil {
				return nil, err
			}
			manifest.Files = append(manifest.Files, "files/")
		}
	}

	buf, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), append(buf, '\n'), 0o600); err != nil {
		return nil, err
	}

	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: the path is named by the operator on the command line
	if err != nil {
		return nil, fmt.Errorf("backup: create %s: %w", path, err)
	}
	defer func() { _ = out.Close() }()

	var sink io.WriteCloser = nopCloser{out}
	var ageWriter io.WriteCloser
	var armorWriter io.WriteCloser
	if passphrase != "" {
		recipient, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return nil, fmt.Errorf("backup: %w", err)
		}
		armorWriter = armor.NewWriter(out)
		ageWriter, err = age.Encrypt(armorWriter, recipient)
		if err != nil {
			return nil, fmt.Errorf("backup: %w", err)
		}
		sink = ageWriter
	}

	if err := writeTarGz(sink, staging); err != nil {
		return nil, err
	}
	if ageWriter != nil {
		if err := ageWriter.Close(); err != nil {
			return nil, err
		}
		if err := armorWriter.Close(); err != nil {
			return nil, err
		}
	}
	if err := out.Sync(); err != nil {
		return nil, err
	}
	info, err := out.Stat()
	if err != nil {
		return nil, err
	}

	res := &Result{Path: path, Bytes: info.Size(), Encrypted: passphrase != ""}
	keep := opts.Keep
	if keep == 0 {
		keep = cfg.Backup.Keep
	}
	if keep > 0 {
		pruned, err := prune(dir, keep)
		if err != nil {
			return res, err
		}
		res.Pruned = pruned
	}
	return res, nil
}

// snapshotSQLite uses VACUUM INTO for a consistent copy of a live database.
func snapshotSQLite(ctx context.Context, cfg *config.Config, dest string) error {
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// VACUUM INTO refuses to overwrite, which is what we want.
	_ = os.Remove(dest)
	if _, err := st.DB().ExecContext(ctx, "VACUUM INTO ?", filepath.ToSlash(dest)); err != nil {
		return fmt.Errorf("backup: sqlite snapshot: %w", err)
	}
	return nil
}

// RestoreOptions drive Restore.
type RestoreOptions struct {
	Config     *config.Config
	Archive    string
	Passphrase string
	// IncludeConfig also restores peek.toml and master.key.
	IncludeConfig bool
	DryRun        bool
}

// Restore unpacks an archive over the configured locations.
func Restore(ctx context.Context, opts RestoreOptions) (*Manifest, error) {
	cfg := opts.Config
	if cfg == nil {
		return nil, errors.New("restore: missing configuration")
	}
	f, err := os.Open(opts.Archive) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var source io.Reader = f
	if strings.HasSuffix(opts.Archive, ".age") {
		if opts.Passphrase == "" {
			return nil, errors.New("restore: this archive is encrypted; pass --passphrase")
		}
		identity, err := age.NewScryptIdentity(opts.Passphrase)
		if err != nil {
			return nil, err
		}
		decrypted, err := age.Decrypt(armor.NewReader(f), identity)
		if err != nil {
			return nil, fmt.Errorf("restore: cannot decrypt the archive: %w", err)
		}
		source = decrypted
	}

	staging, err := os.MkdirTemp("", "peek-restore-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(staging) }()

	if err := extractTarGz(source, staging); err != nil {
		return nil, err
	}

	var manifest Manifest
	buf, err := os.ReadFile(filepath.Join(staging, "manifest.json")) //nolint:gosec // G304: the path is named by the operator on the command line
	if err != nil {
		return nil, errors.New("restore: this does not look like a Peek backup (no manifest.json)")
	}
	if err := json.Unmarshal(buf, &manifest); err != nil {
		return nil, fmt.Errorf("restore: unreadable manifest: %w", err)
	}
	if manifest.Version > manifestVersion {
		return nil, fmt.Errorf("restore: archive format %d is newer than this binary understands (%d)", manifest.Version, manifestVersion)
	}
	if opts.DryRun {
		return &manifest, nil
	}

	if cfg.Database.Driver == "postgres" {
		src := filepath.Join(staging, "peek.dump")
		if _, err := os.Stat(src); err != nil {
			return nil, errors.New("restore: the archive holds no PostgreSQL dump. " +
				"An archive taken from a SQLite instance cannot be restored into PostgreSQL")
		}
		// --clean, because restoring into a database that already has Peek's
		// tables otherwise fails on every CREATE. It is inside one
		// transaction, so a failure leaves the database as it was.
		if err := restorePostgres(ctx, cfg, src, true); err != nil {
			return nil, err
		}
	}

	if cfg.Database.Driver == "sqlite" {
		src := filepath.Join(staging, "peek.db")
		if _, err := os.Stat(src); err != nil {
			return nil, errors.New("restore: the archive holds no database snapshot")
		}
		dest := cfg.Database.DSN
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return nil, err
		}
		// Keep the current database next to the restored one: an operator who
		// restores the wrong archive should not lose the live data.
		if _, err := os.Stat(dest); err == nil {
			aside := dest + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z")
			if err := os.Rename(dest, aside); err != nil {
				return nil, fmt.Errorf("restore: cannot move the current database aside: %w", err)
			}
			// WAL and shm files belong to the old database.
			_ = os.Remove(dest + "-wal")
			_ = os.Remove(dest + "-shm")
		}
		if err := copyFile(src, dest); err != nil {
			return nil, err
		}
	}

	if filesDir := filepath.Join(staging, "files"); dirExists(filesDir) && cfg.Storage.Backend == "local" {
		if err := copyTree(filesDir, cfg.Storage.Path); err != nil {
			return nil, err
		}
	}

	if opts.IncludeConfig {
		if err := copyFile(filepath.Join(staging, "peek.toml"), configPathOf(cfg)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if cfg.MasterKeyFile != "" {
			if err := copyFile(filepath.Join(staging, "master.key"), cfg.MasterKeyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			_ = os.Chmod(cfg.MasterKeyFile, 0o400)
		}
	}
	return &manifest, nil
}

// prune keeps the newest n archives and deletes the rest.
func prune(dir string, keep int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var archives []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "peek-") {
			continue
		}
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tar.gz.age") {
			archives = append(archives, name)
		}
	}
	// Names are timestamped, so lexical order is chronological.
	sortStrings(archives)
	if len(archives) <= keep {
		return nil, nil
	}
	var pruned []string
	for _, name := range archives[:len(archives)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return pruned, err
		}
		pruned = append(pruned, name)
	}
	return pruned, nil
}

// List returns the archives in a directory, newest first.
func List(dir string) ([]os.FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []os.FileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "peek-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, info)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ModTime().After(out[j-1].ModTime()); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

func configPathOf(cfg *config.Config) string {
	if v := os.Getenv("PEEK_CONFIG"); v != "" {
		return v
	}
	_ = cfg
	return config.DefaultPath
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: the path is named by the operator on the command line
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		return copyFile(path, target)
	})
}

func writeTarGz(w io.Writer, root string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // G304: a path inside the backup directory or the staging tree, both owned by this process
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func extractTarGz(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("restore: not a gzip archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// Refuse path traversal: an archive is untrusted input.
		clean := filepath.Clean(filepath.FromSlash(header.Name))
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("restore: refusing suspicious path %q in the archive", header.Name)
		}
		target := filepath.Join(dest, clean)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: a path inside the backup directory or the staging tree, both owned by this process
			if err != nil {
				return err
			}
			// Bound the copy: a crafted archive must not fill the disk silently.
			if _, err := io.CopyN(out, tr, 8<<30); err != nil && !errors.Is(err, io.EOF) {
				_ = out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			// Symlinks and devices have no place in a Peek backup.
			continue
		}
	}
}
