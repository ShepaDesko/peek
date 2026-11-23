package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The password must not reach argv or the environment.
//
// The first version of this code put the whole DSN in PGDATABASE, which
// libpq does not expand — so pg_dump connected to the local socket as the
// current user and reported "role root does not exist", a message that says
// nothing about the real cause. It was found by running a backup on a real
// PostgreSQL host, not by reading the code.

func TestPgEnvKeepsThePasswordOutOfTheEnvironment(t *testing.T) {
	const password = "a-database-password-nobody-should-see"
	dir := t.TempDir()

	pg, err := pgEnvFromDSN(
		"postgres://peek:"+password+"@db.internal:5433/peekdb?sslmode=verify-full", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.cleanup()

	for _, entry := range pg.env {
		if strings.Contains(entry, password) {
			t.Fatalf("the password is in the environment: %s", entry)
		}
	}
	// PGDATABASE must be the database name, not the whole DSN: libpq expands
	// a URI only when it arrives as a parameter, never from the environment.
	if !hasEnv(pg.env, "PGDATABASE=peekdb") {
		t.Errorf("PGDATABASE is wrong:\n%s", strings.Join(pg.env, "\n"))
	}
	for _, want := range []string{
		"PGHOST=db.internal", "PGPORT=5433", "PGUSER=peek", "PGSSLMODE=verify-full",
		"PGAPPNAME=peek-backup",
	} {
		if !hasEnv(pg.env, want) {
			t.Errorf("missing %s", want)
		}
	}

	// The password is in a 0600 file, which libpq requires, and nowhere else.
	if pg.passwordFile == "" {
		t.Fatal("no password file")
	}
	info, err := os.Stat(pg.passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		// Windows does not carry POSIX modes; the check is for the hosts that
		// actually run this.
		if os.Getenv("GOOS") != "windows" && !isWindows() {
			t.Errorf("the password file is %04o, and libpq refuses anything but 0600", perm)
		}
	}
	content, err := os.ReadFile(pg.passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), password) {
		t.Error("the password file does not hold the password")
	}
	if got, want := strings.TrimSpace(string(content)),
		"db.internal:5433:peekdb:peek:"+password; got != want {
		t.Errorf("pgpass line = %q, want %q", got, want)
	}

	// And it is gone afterwards.
	pg.cleanup()
	if _, err := os.Stat(pg.passwordFile); !os.IsNotExist(err) {
		t.Error("the password file survived cleanup")
	}
}

func TestPgEnvAcceptsBothDSNForms(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]map[string]string{
		"postgres://peek@127.0.0.1:5432/peek": {
			"PGUSER": "peek", "PGHOST": "127.0.0.1", "PGPORT": "5432", "PGDATABASE": "peek",
		},
		"postgresql://peek:pw@db/peek?sslmode=disable": {
			"PGUSER": "peek", "PGHOST": "db", "PGDATABASE": "peek", "PGSSLMODE": "disable",
		},
		"host=db.internal port=6432 user=peek dbname=peek sslmode=require": {
			"PGHOST": "db.internal", "PGPORT": "6432", "PGUSER": "peek",
			"PGDATABASE": "peek", "PGSSLMODE": "require",
		},
		// libpq allows a quoted value, which is how a password with a space
		// is written in the key/value form.
		"host=db user=peek password='a b c' dbname=peek": {
			"PGHOST": "db", "PGUSER": "peek", "PGDATABASE": "peek",
		},
	}
	for dsn, want := range cases {
		pg, err := pgEnvFromDSN(dsn, dir)
		if err != nil {
			t.Errorf("%s: %v", dsn, err)
			continue
		}
		for key, value := range want {
			if !hasEnv(pg.env, key+"="+value) {
				t.Errorf("%s: missing %s=%s", dsn, key, value)
			}
		}
		if strings.Contains(dsn, "password") {
			content, _ := os.ReadFile(pg.passwordFile)
			if !strings.Contains(string(content), "a b c") && !strings.Contains(string(content), "pw") {
				t.Errorf("%s: the password did not reach the password file", dsn)
			}
		}
		pg.cleanup()
	}
}

func TestPgEnvRefusesWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	for _, dsn := range []string{
		"",
		"/var/lib/peek/peek.db",          // a SQLite path
		"postgres://peek@db:5432/",       // no database
		"host=db user=peek",              // no database
		"host=db password='unterminated", // a quote that never closes
	} {
		if _, err := pgEnvFromDSN(dsn, dir); err == nil {
			t.Errorf("%q was accepted", dsn)
		}
	}
}

// TestPgpassEscaping: a colon in a password or a host would otherwise shift
// every field after it, and libpq would use the wrong one silently.
func TestPgpassEscaping(t *testing.T) {
	dir := t.TempDir()
	pg, err := pgEnvFromDSN("postgres://pe%3Aek:pa%3Ass@[2001:db8::1]:5432/peek", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.cleanup()

	content, err := os.ReadFile(pg.passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(content))
	// Five fields, whatever the values contained.
	fields := splitPgpass(line)
	if len(fields) != 5 {
		t.Fatalf("pgpass line %q splits into %d fields, want 5", line, len(fields))
	}
	if fields[0] != "2001:db8::1" {
		t.Errorf("host = %q", fields[0])
	}
	if fields[3] != "pe:ek" || fields[4] != "pa:ss" {
		t.Errorf("user = %q, password = %q", fields[3], fields[4])
	}
}

// splitPgpass is the reader libpq implements, written here so the escaping
// above is checked against something other than itself.
func splitPgpass(line string) []string {
	var fields []string
	var current strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line):
			i++
			current.WriteByte(line[i])
		case line[i] == ':':
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteByte(line[i])
		}
	}
	return append(fields, current.String())
}

func hasEnv(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}

func isWindows() bool {
	return filepath.Separator == '\\'
}

// TestPgEnvReturnsTheDatabaseName: pg_restore needs it as -d. Without that
// flag it writes a script to stdout instead of restoring, and then refuses
// --clean and --single-transaction as conflicting with the implied -f — which
// is a confusing way to say "you forgot -d", and is how this was found.
func TestPgEnvReturnsTheDatabaseName(t *testing.T) {
	dir := t.TempDir()
	for dsn, want := range map[string]string{
		"postgres://peek:pw@db:5432/peekdb":          "peekdb",
		"host=db user=peek dbname=other password=pw": "other",
	} {
		pg, err := pgEnvFromDSN(dsn, dir)
		if err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
		if pg.dbname != want {
			t.Errorf("%s: dbname = %q, want %q", dsn, pg.dbname, want)
		}
		pg.cleanup()
	}
}
