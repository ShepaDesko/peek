# CLAUDE.md

Working notes for this repository. Short on purpose — the reasoning lives in
`docs/`, and `SPEC.md` is the original brief.

## Commands

```bash
make deps          # Go modules + npm install
make build         # build the SPA, embed it, produce bin/peek
make build-go      # Go only, skip the frontend build
make test          # go test -race + vitest (shared crypto vectors)
make lint          # gofmt, go vet, golangci-lint, ESLint
make fmt           # gofmt + prettier
make vectors       # regenerate crypto/vectors/v1.json
make dev-config    # write peek.dev.toml and .dev/
make dev           # API on :8080 + Vite on :5173
make snapshot      # local GoReleaser build, no publishing
```

Single tests:

```bash
go test ./internal/server/ -run TestConcurrentRevealOverHTTP -v
npm run test --prefix web -- crypto
```

## Rules that are not negotiable

1. **Never log** a secret, key, passphrase, URL fragment, read token or request
   body. The access log records the matched route pattern, never the URL — a
   path carries a secret identifier.
2. **No Docker anywhere**, including the documentation. The product is a native
   Linux binary run by systemd. Docker is tolerated only in CI, if ever needed.
3. **Nothing external at runtime in the browser**: no CDN, no web font, no
   analytics, no third-party script. Everything is embedded in the binary.
4. **No outbound call by default** from the server, except configured SMTP, an
   IdP, webhooks and the update check. Peek must run air-gapped.
5. **Security before convenience.** When the choice is "practical" or "safe",
   pick safe and say so.
6. **Half-built features refuse loudly** with the milestone named, rather than
   falling back silently (see `postgres`, `acme`).

## Shape of the code

- `internal/crypto` (Go) and `web/src/crypto` (TypeScript) are two
  implementations of **one** format. Change one and you change both, then run
  `make vectors` — CI fails if `crypto/vectors/v1.json` moves without the
  implementations agreeing.
- `internal/secrets` holds policy and lifecycle rules; `internal/store` holds
  SQL; `internal/server` holds HTTP. Keep them that way.
- Handlers are in `internal/server`, not a separate `internal/api` (see
  `docs/DECISIONS.md`).

## Traps worth remembering

- **Go package patterns exclude `web/node_modules`**, which ships a stray Go
  package from a frontend dependency: use `./cmd/... ./internal/... ./tools/...`
  (the `$(PKGS)` variable in the Makefile), not `./...`.
- **`-race` needs CGO**, so it does not run on a Windows dev box without a C
  toolchain. CI runs it on Linux; run `go test $(PKGS)` locally.
- **go-toml has no duration type.** `config.Duration` implements
  `encoding.TextMarshaler`, which is why `peek.toml` can say `30d`. Use
  `.Std()` to get a `time.Duration`.
- **`internal/webui/dist` only has a `.gitignore` committed.** `go build` works
  without Node (a placeholder page is served); `make web-build` fills it.
- **The CSP needs `'wasm-unsafe-eval'`** or Argon2id cannot run. Do not
  "tidy it away".
- **Frontend fallback colours live in `@layer base`** so the unlayered
  `/branding.css` overrides them. Moving them out of the layer silently breaks
  white-labelling.
- **SQLite uses `_txlock=immediate` and one connection.** The single-read
  guarantee comes from the conditional `UPDATE` and its row count, not from
  that: keep it that way so PostgreSQL behaves identically.
- **`peek doctor` exits non-zero on FAIL**, so it is usable in Ansible and in
  monitoring. Do not turn failures into warnings to make it quiet.

## Conventions

- Conventional Commits (`feat:`, `fix:`, `docs:`, `sec:`, `chore:`), scoped by
  area where it helps: `feat(server): …`.
- Comments explain **why**, not what. Dense or security-relevant code deserves
  a sentence; obvious code deserves none.
- Interface strings go through `web/src/lib/i18n.ts` in both French and
  English. French is the default language.
- Every new endpoint: decide **public or internal listener**, add it to the
  right group in `Server.Handler`, and document it in `docs/API.md`.
