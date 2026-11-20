package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The store tests run against every backend available on the machine.
//
// SQLite always runs. PostgreSQL runs when PEEK_TEST_POSTGRES_DSN is set,
// which CI does through a service container and which a developer can do
// against any instance. Each PostgreSQL test gets a private schema, so the
// suite is parallel-safe and leaves nothing behind.

const postgresEnv = "PEEK_TEST_POSTGRES_DSN"

type backend struct {
	name string
	open func(t *testing.T) *store.Store
}

func backends(t *testing.T) []backend {
	t.Helper()
	list := []backend{{name: "sqlite", open: openSQLite}}
	if dsn := os.Getenv(postgresEnv); dsn != "" {
		list = append(list, backend{name: "postgres", open: openPostgres})
	}
	return list
}

func openSQLite(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func openPostgres(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv(postgresEnv)
	if dsn == "" {
		t.Skipf("%s is not set", postgresEnv)
	}

	schema := fmt.Sprintf("peek_test_%d", time.Now().UnixNano())
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	scoped := withSearchPath(dsn, schema)
	s, err := store.Open(context.Background(), config.Database{Driver: "postgres", DSN: scoped})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
		cleanup, err := sql.Open("pgx", dsn)
		if err != nil {
			return
		}
		defer func() { _ = cleanup.Close() }()
		_, _ = cleanup.Exec("DROP SCHEMA " + schema + " CASCADE")
	})
	return s
}

// withSearchPath adds a search_path option to a DSN in either supported form.
func withSearchPath(dsn, schema string) string {
	option := "search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + "options=-c%20search_path%3D" + schema
	}
	return dsn + " options='-c " + option + "'"
}

// run executes fn against every available backend, as a subtest each.
func run(t *testing.T, fn func(t *testing.T, s *store.Store)) {
	t.Helper()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			fn(t, b.open(t))
		})
	}
}
