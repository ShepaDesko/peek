package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations
var migrationFS embed.FS

// Migration is one versioned schema step, embedded in the binary so that an
// upgrade needs no extra files on disk.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

func (s *Store) migrations() ([]Migration, error) {
	dir := path.Join("migrations", s.driver)
	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		return nil, fmt.Errorf("store: no migrations for driver %q: %w", s.driver, err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("store: migration %q must be named NNNN_name.sql", e.Name())
		}
		version, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q has a non-numeric version", e.Name())
		}
		buf, err := migrationFS.ReadFile(path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: version, Name: e.Name(), SQL: string(buf)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Migrate applies every pending migration. It runs at every start, which is
// what makes peek update a single step: replace the binary, restart.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}
	all, err := s.migrations()
	if err != nil {
		return err
	}
	for _, m := range all {
		if applied[m.Version] {
			continue
		}
		// Each migration runs in its own transaction: a failure leaves the
		// database on the previous version rather than half migrated.
		err := s.tx(ctx, func(tx *sql.Tx) error {
			for _, stmt := range splitStatements(m.SQL) {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("%w (statement: %s)", err, firstLine(stmt))
				}
			}
			_, err := tx.ExecContext(ctx,
				s.rebind(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`),
				m.Version, m.Name, unix(s.Now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("store: migration %s failed: %w", m.Name, err)
		}
	}
	return nil
}

// MigrationStatus reports applied and pending versions, for peek migrate status.
func (s *Store) MigrationStatus(ctx context.Context) (appliedVersions []int, pending []Migration, err error) {
	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return nil, nil, err
	}
	all, err := s.migrations()
	if err != nil {
		return nil, nil, err
	}
	for _, m := range all {
		if applied[m.Version] {
			appliedVersions = append(appliedVersions, m.Version)
		} else {
			pending = append(pending, m)
		}
	}
	sort.Ints(appliedVersions)
	return appliedVersions, pending, nil
}

func (s *Store) appliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := s.query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

// firstLine shortens a statement for an error message.
func firstLine(stmt string) string {
	if idx := strings.IndexByte(stmt, '\n'); idx > 0 {
		stmt = stmt[:idx]
	}
	if len(stmt) > 120 {
		stmt = stmt[:120] + "…"
	}
	return strings.TrimSpace(stmt)
}
