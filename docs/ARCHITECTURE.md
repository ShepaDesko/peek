# Architecture

## One binary

```
peek (about 13 MB, static, CGO disabled)
├── HTTP server, routing and hardening middleware
├── secret lifecycle and policy
├── SQLite access and embedded migrations
├── the compiled React interface (go:embed)
├── background jobs (purge, audit retention)
└── admin commands (setup, doctor, backup, restore, update…)
```

No runtime to install, no asset directory, no Docker. Deployment is a file plus
a systemd unit.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/peek` | Command dispatch, the `serve` loop, logging setup |
| `cmd/peek-cli` | Terminal client: `push`, `get` — the same crypto as the browser |
| `internal/config` | Load and validate `peek.toml`; readable durations; redaction |
| `internal/crypto` | Format v1: derivation, sealing, identifiers, fragments |
| `internal/store` | Schema, migrations, secret lifecycle, audit trail |
| `internal/secrets` | Policy enforcement, reveal rules, purge |
| `internal/server` | Routes, middleware, handlers, listeners, real client IP |
| `internal/branding` | Theme resolution, palette generation, contrast checks |
| `internal/webui` | The embedded SPA |
| `internal/jobs` | Periodic purge and audit trimming |
| `internal/setup` | The `peek setup` assistant |
| `internal/doctor` | Diagnostics, including the external checks |
| `internal/backup` | Hot backups, age encryption, restore |
| `internal/update` | Release discovery, checksum and signature verification, swap |
| `web/` | React interface; `web/src/crypto` is the TypeScript reference |
| `crypto/vectors` | Shared test vectors binding Go and TypeScript together |

Dependencies point one way: `server` then `secrets` then `store` then `crypto`.
`config` and `crypto` depend on nothing of ours.

## A request, end to end

Creating a secret:

```
browser                         peek
  │ generate id, key, salt
  │ derive enc + read token
  │ seal payload
  ├── POST /api/v1/secrets ────► withContext      resolve the real client IP
  │                              securityHeaders  CSP, no-referrer, noindex
  │                              internalOnly     refuse on the public listener
  │                              restrictCIDR     create_allowed_cidrs
  │                              rateLimit        token bucket per IP
  │                              handleCreate     decode, validate shapes
  │                              secrets.Create   policy: TTL, reads, size, KDF floor
  │                              store.Create     insert, reject a duplicate id
  │                              audit            secret.created (no content)
  ◄── 201 {id, expires_at} ─────┤
  │ build the links locally (the key never left)
```

Revealing:

```
GET  /api/v1/secrets/{id}   metadata only, audit secret.page_viewed, no read spent
POST /api/v1/secrets/{id}/reveal
     constant-time compare of SHA-256(read token)
     mismatch -> failure counter, 403 with attempts left, nothing released
     match    -> transaction -> conditional UPDATE -> row count must be 1
                 last read   -> delete the row, write the tombstone
     200 {ciphertext}  -> decrypted in the browser
```

## The two listeners

`Server.Handler(role)` builds a router per listener. Routes that belong to the
sender or the administrator are wrapped in `internalOnly`, which refuses them
on the public listener whatever the path — so a routing mistake cannot expose
the admin surface. The CIDR gates are a second, independent lock.

## Data model

`secrets` holds live secrets only. A secret that is read, expired, burned or
locked is deleted and replaced by a row in `secret_tombstones` (status and
counters, no content), so the sender's receipt page still works.
`audit_events` is append-only and never records content, keys or fragments.

## Frontend

React 19, Vite, Tailwind 4, no router dependency (three routes), no UI library,
no network call except to this same origin. `web/src/crypto` is a standalone
module with no React dependency — the same code a future SDK would publish.
The build is copied into `internal/webui/dist` and embedded; only a
`.gitignore` is committed there, so `go build` works on a fresh checkout
without Node installed.

## Concurrency

SQLite runs in WAL mode with `_txlock=immediate` and a single connection, which
serialises writers and removes `SQLITE_BUSY` churn at this request volume. The
single-read guarantee does not rely on that: it comes from the conditional
`UPDATE` and its row count, which holds on PostgreSQL and across nodes too.

## Observability

Structured JSON logs on stdout for journald. The access log records the matched
route pattern — never the URL — because a path contains a secret identifier and
a fragment must never reach a log at all. `/healthz` is liveness, `/readyz`
checks the database, and `/api/v1/ip` reports the resolved client IP for
diagnosing a proxy.
