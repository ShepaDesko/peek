package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pure Go PostgreSQL driver, no CGO
)

// openPostgres connects to PostgreSQL and applies the pending migrations.
//
// PostgreSQL is what makes several Peek nodes possible: the single-read
// guarantee comes from a conditional UPDATE and its row count, which behaves
// the same here as on SQLite, and the periodic jobs coordinate through the
// job_locks table rather than assuming one process.
func openPostgres(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("store: empty postgres DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}

	// Sized for a single Peek node in front of a shared database. Each node
	// keeps its own small pool rather than one large shared one.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(time.Hour)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: cannot reach the postgres database: %w", err)
	}

	s := &Store{db: db, driver: "postgres", now: time.Now}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// splitStatements breaks a migration file into individual statements.
//
// The PostgreSQL protocol refuses several statements in one prepared exec, so
// migrations are applied one statement at a time. Quoted strings and comments
// are respected; dollar-quoted bodies are not used by any Peek migration and
// would need handling here if that ever changes.
func splitStatements(script string) []string {
	var (
		out       []string
		current   strings.Builder
		inSingle  bool
		inDouble  bool
		inComment bool
	)
	runes := []rune(script)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		next := rune(0)
		if i+1 < len(runes) {
			next = runes[i+1]
		}

		switch {
		case inComment:
			current.WriteRune(c)
			if c == '\n' {
				inComment = false
			}
			continue
		case !inSingle && !inDouble && c == '-' && next == '-':
			inComment = true
			current.WriteRune(c)
			continue
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ';' && !inSingle && !inDouble:
			if stmt := strings.TrimSpace(current.String()); stmt != "" {
				out = append(out, stmt)
			}
			current.Reset()
			continue
		}
		current.WriteRune(c)
	}
	if stmt := strings.TrimSpace(current.String()); stmt != "" {
		out = append(out, stmt)
	}
	return out
}
