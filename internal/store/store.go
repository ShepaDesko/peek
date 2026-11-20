// Package store is the data layer: schema migrations, secret lifecycle and
// the append-only audit trail.
//
// The SQL is written to stay portable between SQLite (default, single node)
// and PostgreSQL (multi node). Placeholders are written as ? and rewritten per
// driver by rebind, so the only driver-specific code is in the open path.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"

	_ "modernc.org/sqlite" // pure Go SQLite driver, no CGO
)

// Errors returned by the store. Callers map them to generic HTTP answers: the
// recipient-facing API must not distinguish "gone" from "never existed".
var (
	ErrNotFound  = errors.New("store: not found")
	ErrConflict  = errors.New("store: identifier already used")
	ErrExhausted = errors.New("store: no view left")
	ErrBadToken  = errors.New("store: token mismatch")
)

// Store is a handle on the database.
type Store struct {
	db     *sql.DB
	driver string
	now    func() time.Time
}

// DB exposes the underlying handle for maintenance commands (backup, doctor).
func (s *Store) DB() *sql.DB { return s.db }

// Driver returns the driver name in use.
func (s *Store) Driver() string { return s.driver }

// Now returns the store clock, overridable in tests.
func (s *Store) Now() time.Time { return s.now().UTC() }

// SetClock replaces the clock. Tests only.
func (s *Store) SetClock(f func() time.Time) { s.now = f }

// Open connects to the configured database and applies pending migrations.
func Open(ctx context.Context, cfg config.Database) (*Store, error) {
	switch cfg.Driver {
	case "sqlite":
		return openSQLite(ctx, cfg.DSN)
	case "postgres":
		return openPostgres(ctx, cfg.DSN)
	default:
		return nil, fmt.Errorf("store: unknown driver %q", cfg.Driver)
	}
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ping checks the database answers, for /readyz and peek doctor.
func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.db.PingContext(ctx)
}

// rebind turns ? placeholders into the driver dialect.
func (s *Store) rebind(query string) string {
	if s.driver != "postgres" {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.rebind(query), args...)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.rebind(query), args...)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.rebind(query), args...)
}

// tx runs fn in a transaction, rolling back on error.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
