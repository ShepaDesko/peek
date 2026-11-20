package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// openSQLite opens the database in WAL mode with an immediate-transaction
// default. Immediate locking is what makes the single-view guarantee hold
// under concurrency: the view decrement takes the write lock up front instead
// of discovering a conflict at commit time.
func openSQLite(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: empty sqlite path")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("store: create %s: %w", dir, err)
			}
		}
	}

	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + filepath.ToSlash(path)
	}
	params := url.Values{}
	params.Set("_txlock", "immediate")
	params.Add("_pragma", "journal_mode(WAL)")
	params.Add("_pragma", "synchronous(NORMAL)")
	params.Add("_pragma", "busy_timeout(10000)")
	params.Add("_pragma", "foreign_keys(ON)")
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + params.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	// SQLite allows exactly one writer. Serialising connections here removes
	// SQLITE_BUSY churn and costs nothing at Peek's request volume.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: cannot reach sqlite database %s: %w", path, err)
	}

	s := &Store{db: db, driver: "sqlite", now: time.Now}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// OpenMemory opens a private in-memory database. Tests only.
func OpenMemory(ctx context.Context) (*Store, error) {
	return openSQLite(ctx, "file:peek-test-"+randomSuffix()+"?mode=memory&cache=shared")
}

func randomSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
