package backup

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Turning a PostgreSQL DSN into an environment pg_dump will accept, without
// the password reaching anywhere it can be read.
//
// Three places a password must not go, in order of how badly:
//
//   - argv. /proc/<pid>/cmdline is world-readable, so `pg_dump "$DSN"` hands
//     the database password to every user on the host for as long as the dump
//     runs. This is the mistake the first version of this file made.
//   - the environment. /proc/<pid>/environ is readable by the same user and
//     by root only, which is tolerable but still visible to anything running
//     as the service account.
//   - a file somebody forgets to delete.
//
// So: every connection parameter except the password goes in the environment,
// and the password goes into a 0600 password file that is removed when the
// dump finishes. That is the mechanism libpq itself documents for exactly
// this, which is also why pg_dump needs no flag to use it.
//
// PGDATABASE deliberately does *not* carry the whole DSN. libpq expands a
// `dbname` that looks like a URI only when it arrives as a parameter, never
// when it arrives from the environment — so `PGDATABASE=postgres://…` makes
// pg_dump connect to the local socket as the current user and look for a
// database with a very long name. On a Debian host running as root that
// surfaces as `le rôle « root » n'existe pas`, which says nothing about the
// real cause.

// pgEnvironment is what to put in the environment, plus the temporary
// password file to remove afterwards.
type pgEnvironment struct {
	env          []string
	passwordFile string
	// dbname is also returned because pg_restore needs it as -d: without
	// that flag it writes a script to stdout instead of restoring, and
	// --clean and --single-transaction then conflict with the implied -f.
	// PGDATABASE is not enough.
	dbname string
}

// cleanup removes the password file. Always called, including on failure.
func (p pgEnvironment) cleanup() {
	if p.passwordFile != "" {
		_ = os.Remove(p.passwordFile)
	}
}

// pgEnvFromDSN parses a DSN in either of the two forms libpq accepts — a URI
// (`postgres://user:pass@host:5432/db?sslmode=verify-full`) or a key/value
// conninfo string (`host=db user=peek password=… dbname=peek`) — and returns
// the environment to run pg_dump with.
func pgEnvFromDSN(dsn, tempDir string) (pgEnvironment, error) {
	params, err := parsePgDSN(dsn)
	if err != nil {
		return pgEnvironment{}, err
	}
	if params["dbname"] == "" {
		return pgEnvironment{}, fmt.Errorf("backup: database.dsn names no database")
	}

	out := pgEnvironment{
		env:    append(os.Environ(), "PGCONNECT_TIMEOUT=10"),
		dbname: params["dbname"],
	}

	// Everything except the password.
	for key, envName := range map[string]string{
		"host":             "PGHOST",
		"port":             "PGPORT",
		"user":             "PGUSER",
		"dbname":           "PGDATABASE",
		"sslmode":          "PGSSLMODE",
		"sslrootcert":      "PGSSLROOTCERT",
		"sslcert":          "PGSSLCERT",
		"sslkey":           "PGSSLKEY",
		"application_name": "PGAPPNAME",
	} {
		if value := params[key]; value != "" {
			out.env = append(out.env, envName+"="+value)
		}
	}
	if params["application_name"] == "" {
		out.env = append(out.env, "PGAPPNAME=peek-backup")
	}

	if password := params["password"]; password != "" {
		file, err := writePasswordFile(tempDir, params, password)
		if err != nil {
			return pgEnvironment{}, err
		}
		out.passwordFile = file
		out.env = append(out.env, "PGPASSFILE="+file)
	}
	return out, nil
}

// writePasswordFile writes a one-line .pgpass. libpq refuses one that is not
// 0600, which is a check worth having rather than working around.
func writePasswordFile(dir string, params map[string]string, password string) (string, error) {
	host := params["host"]
	if host == "" {
		host = "localhost"
	}
	port := params["port"]
	if port == "" {
		port = "5432"
	}
	line := strings.Join([]string{
		escapePgpass(host),
		escapePgpass(port),
		escapePgpass(params["dbname"]),
		escapePgpass(orStar(params["user"])),
		escapePgpass(password),
	}, ":") + "\n"

	path := filepath.Join(dir, ".pgpass")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		return "", fmt.Errorf("backup: cannot write the password file: %w", err)
	}
	return path, nil
}

// escapePgpass escapes the two characters the format gives meaning to.
func escapePgpass(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, ":", `\:`)
}

func orStar(value string) string {
	if value == "" {
		return "*"
	}
	return value
}

// parsePgDSN returns the libpq parameters a DSN carries.
func parsePgDSN(dsn string) (map[string]string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, fmt.Errorf("backup: database.dsn is empty")
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return parsePgURI(dsn)
	}
	if !strings.Contains(dsn, "=") {
		return nil, fmt.Errorf("backup: database.dsn is neither a postgres:// URI nor a key=value connection string")
	}
	return parsePgKeyValue(dsn)
}

func parsePgURI(dsn string) (map[string]string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("backup: database.dsn: %w", err)
	}
	params := map[string]string{}
	if u.User != nil {
		params["user"] = u.User.Username()
		if password, ok := u.User.Password(); ok {
			params["password"] = password
		}
	}
	if u.Host != "" {
		host, port, splitErr := net.SplitHostPort(u.Host)
		if splitErr != nil {
			params["host"] = u.Host
		} else {
			params["host"], params["port"] = host, port
		}
	}
	params["dbname"] = strings.TrimPrefix(u.Path, "/")
	for key, values := range u.Query() {
		if len(values) > 0 && values[0] != "" {
			params[key] = values[0]
		}
	}
	return params, nil
}

// parsePgKeyValue handles the `host=db user=peek password='a b'` form,
// including the single quoting libpq allows around a value with spaces.
func parsePgKeyValue(dsn string) (map[string]string, error) {
	params := map[string]string{}
	rest := dsn
	for {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return params, nil
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return nil, fmt.Errorf("backup: database.dsn: %q has no value", rest)
		}
		key := strings.TrimSpace(rest[:eq])
		rest = strings.TrimLeft(rest[eq+1:], " \t")

		var value string
		switch {
		case strings.HasPrefix(rest, "'"):
			end := 1
			var b strings.Builder
			for end < len(rest) && rest[end] != '\'' {
				if rest[end] == '\\' && end+1 < len(rest) {
					end++
				}
				b.WriteByte(rest[end])
				end++
			}
			if end >= len(rest) {
				return nil, fmt.Errorf("backup: database.dsn: unterminated quote after %q", key)
			}
			value, rest = b.String(), rest[end+1:]
		default:
			space := strings.IndexAny(rest, " \t")
			if space < 0 {
				value, rest = rest, ""
			} else {
				value, rest = rest[:space], rest[space:]
			}
		}
		params[key] = value
	}
}
