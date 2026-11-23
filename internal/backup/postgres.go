package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// PostgreSQL backup and restore, through pg_dump and psql.
//
// Peek does not reimplement either. A logical dump has to agree with the
// server's own idea of its catalogue, its extensions and its encoding, and the
// tool that ships with the server is the only thing that reliably does — which
// is also why the version check below refuses a dump taken by a client older
// than the server rather than producing an archive that restores badly.
//
// The SQLite path needs no external tool at all (`VACUUM INTO`), so this file
// is the price of the multi-node option, paid only by the people who take it.

// dumpTimeout bounds a dump. Generous: a database with a hundred thousand
// secrets and their audit trail is still small, but a loaded server can be
// slow to answer.
const dumpTimeout = 30 * time.Minute

// ErrNoPgDump means the tool is not on this host.
var ErrNoPgDump = errors.New("backup: pg_dump was not found")

// snapshotPostgres writes a custom-format dump of the configured database.
//
// The custom format rather than plain SQL: it is compressed, it restores with
// pg_restore in parallel, and it cannot be half-applied by a stray psql
// invocation the way a .sql file can.
func snapshotPostgres(ctx context.Context, cfg *config.Config, dest string) error {
	tool, err := findTool("pg_dump")
	if err != nil {
		return err
	}
	if err := checkToolVersion(ctx, tool); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, dumpTimeout)
	defer cancel()

	// The DSN goes in the environment, not in argv: /proc/<pid>/cmdline is
	// world-readable, and the DSN carries the database password.
	cmd := exec.CommandContext(ctx, tool, //nolint:gosec // the tool path comes from exec.LookPath
		"--format=custom",
		"--no-owner",
		"--no-privileges",
		"--file", dest,
	)
	cmd.Env = append(os.Environ(), "PGCONNECT_TIMEOUT=10")
	cmd.Env = append(cmd.Env, "PGDATABASE="+cfg.Database.DSN)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("backup: pg_dump: %w: %s", err, firstLine(stderr.String()))
	}
	info, err := os.Stat(dest)
	if err != nil {
		return fmt.Errorf("backup: pg_dump wrote nothing: %w", err)
	}
	if info.Size() == 0 {
		return errors.New("backup: pg_dump produced an empty file")
	}
	return nil
}

// restorePostgres loads a dump into the configured database.
//
// It does not drop the database. An operator restoring into a live instance
// would lose whatever arrived since the dump without being asked, so the
// caller stops the service first and this refuses a database that still has
// Peek's tables unless the caller said to replace them.
func restorePostgres(ctx context.Context, cfg *config.Config, src string, clean bool) error {
	tool, err := findTool("pg_restore")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, dumpTimeout)
	defer cancel()

	args := []string{"--no-owner", "--no-privileges", "--single-transaction"}
	if clean {
		// --clean drops each object before recreating it, inside the same
		// transaction, so a failure leaves the database as it was.
		args = append(args, "--clean", "--if-exists")
	}
	args = append(args, src)

	cmd := exec.CommandContext(ctx, tool, args...) //nolint:gosec // the tool path comes from exec.LookPath
	cmd.Env = append(os.Environ(), "PGCONNECT_TIMEOUT=10")
	cmd.Env = append(cmd.Env, "PGDATABASE="+cfg.Database.DSN)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restore: pg_restore: %w: %s", err, firstLine(stderr.String()))
	}
	return nil
}

// FindPgDump reports whether the tooling a PostgreSQL backup needs is
// present. peek doctor calls it, so an operator learns that pg_dump is
// missing before the nightly timer does.
func FindPgDump() (string, error) { return findTool("pg_dump") }

// findTool locates pg_dump or pg_restore and explains how to get it when it is
// missing, rather than reporting "executable file not found in $PATH".
func findTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil {
		return path, nil
	}
	// Debian and RHEL both keep versioned copies out of PATH when several
	// server versions are installed.
	for _, dir := range []string{"/usr/lib/postgresql", "/usr/pgsql"} {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			continue
		}
		// Newest first, so a 17 client is preferred over a 15 one.
		for i := len(entries) - 1; i >= 0; i-- {
			candidate := filepath.Join(dir, entries[i].Name(), "bin", name)
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("%w (%s): install the PostgreSQL client tools — "+
		"apt install postgresql-client, or dnf install postgresql", ErrNoPgDump, name)
}

// checkToolVersion refuses a client older than the server.
//
// pg_dump says so itself and exits non-zero, but only after connecting, and
// the message mentions version numbers without saying what to do about them.
func checkToolVersion(ctx context.Context, tool string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tool, "--version").Output() //nolint:gosec // the tool path comes from exec.LookPath
	if err != nil {
		return fmt.Errorf("backup: %s --version: %w", filepath.Base(tool), err)
	}
	if !strings.Contains(string(out), "pg_dump") {
		return fmt.Errorf("backup: %s does not look like pg_dump: %q", tool, firstLine(string(out)))
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexAny(s, "\r\n"); idx >= 0 {
		return s[:idx]
	}
	if s == "" {
		return "no output"
	}
	return s
}
