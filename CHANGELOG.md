# Changelog

All notable changes to Peek are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.0.2] - 2026-11-23

The air-gapped update refused the files a release publishes. Found by running
it on a real offline host rather than by reading the code.

### Fixed

- `peek update --file ARCHIVE` looked for a signature over the archive, and a
  release does not produce one: it signs `checksums.txt` once, and that single
  signature covers every artefact. So the documented offline path answered "no
  signature found for this release. Refusing to install." for every published
  archive — on a product whose claim is that it runs air-gapped. The command
  now looks for `checksums.txt` and its signature next to the archive and
  verifies the same two-step chain it does online, while still accepting an
  `ARCHIVE.minisig` for an operator who signs their own mirror.
- `peek rollback` rejected `--yes` with a usage error. It never asks for
  confirmation, so the flag changes nothing — but an operator reaching for it
  has just had an update go wrong, and that moment does not need a usage
  error. It is accepted and documented as a no-op.

## [1.0.1] - 2026-11-23

A patch release on the same day as 1.0.0: the update path could install the
wrong binary, and that is the path that has to be the most trustworthy of all.
Nothing else changes.

### Fixed

- `peek update` could install `peek-cli` over the server binary. A release
  carries `peek-cli_<v>_<os>_<arch>.tar.gz` beside `peek_<v>_<os>_<arch>.tar.gz`
  and the asset was matched on the suffix alone, so which one won depended on
  the order the release source happened to list them in. The name must now also
  start with `peek_`.
- An entry larger than the extraction cap was copied up to the cap and
  installed truncated, because `io.CopyN` stops at its limit without an error.
  An oversized entry now refuses the update.
- A JWKS entry of a key type Peek does not accept, found in the key cache,
  failed later as "RS256 needs an RSA key" instead of naming the key type. The
  cache path now refuses it the same way the fetch path already did.

### Added

- Tests for `internal/oidc` (76% of statements) and `internal/update` (78%),
  the two packages that verify something on behalf of the operator and had
  none. They assert the properties the documentation claims: no symmetric
  algorithm and no `alg: none`, RSA below 2048 bits refused, an exact issuer
  comparison, an ambiguous key set refused rather than tried in turn, the
  Entra group overflow refused, a discovery document naming another issuer
  refused, the PKCE verifier absent from the authorization URL, a signature
  from an untrusted key refused, and a tampered checksum file refused.

## [1.0.0] - 2026-11-23

First stable release. Everything the brief asked for is implemented, and the
parts that refuse rather than pretend are gone: there is nothing left to
refuse.

Validated on a Debian 13 virtual machine throughout — a single vCPU and 2 GB
of RAM — including a two-node cluster against PostgreSQL 17 behind nginx, a
100 MiB attachment through real TLS, and an S3 backend against Garage.

### Added — milestone M5, accounts and second factors
- PostgreSQL alongside SQLite, with the same migrations and the same
  single-read guarantee: the conditional `UPDATE` and its row count, which is
  what makes the two behave identically under concurrency.
- Shared coordination for several nodes without Redis or a scheduler: named
  leases in `job_locks` for the periodic jobs, and a token bucket spent in one
  upsert so a cluster has one rate limit rather than one per node.
- Local accounts with Argon2id passwords, the four roles (`admin`, `manager`,
  `member`, `auditor`), invitations by e-mail, temporary lockout after failed
  attempts.
- TOTP second factor with recovery codes, and WebAuthn passkeys.
- Sessions as rows: `HttpOnly; Secure; SameSite=Lax`, idle and absolute
  expiry, revocable individually or all at once.
- Sender dashboard, audit export as CSV and JSON, and optional RFC 5424
  syslog forwarding for a SIEM.

### Added — milestone M6, white labelling
- The brand lives in the database, per organisation: name, colours, logos,
  favicon, fonts, corner radius, button style, custom CSS, translatable texts.
- The palette is generated from one primary colour and **checked for
  contrast**: text on the primary surface is whichever of white or near-black
  passes 4.5:1, and the editor says so when neither does.
- Live preview of the home page, the recipient page and an e-mail.
- Branded HTML and text e-mail templates, with a test-send button.
- `peek branding export` / `import`, so a brand can be prepared once and
  deployed at a customer.

### Added — milestone M7, files, several recipients, secret requests
- Attachments up to 100 MiB, encrypted in the browser chunk by chunk with the
  STREAM construction: a 17-byte header, per-chunk nonces and a final-chunk
  flag, so a truncated stream cannot be mistaken for a complete one.
- Local and S3-compatible blob storage. SigV4 is signed by hand — no AWS SDK,
  whose credential chain would probe the instance-metadata endpoint, an
  outbound call Peek promises not to make.
- Multi-recipient secrets: one upload, several links, each with its own key,
  expiry, views and passphrase.
- Secret requests: a link that asks somebody to send *you* something, sealed
  to a P-256 public key only the requester can open.
- A download grant issued by a successful reveal, so a 100 MiB attachment
  stays reachable while the secret row is already gone.

### Added — milestone M8, API, tokens, webhooks, single sign-on
- Scoped API tokens, `peek_<id>.<secret>`: a greppable prefix for leak
  scanners, a public id as the lookup key so a leak can be revoked by name,
  and only a SHA-256 of the secret half stored. Four scopes. A token never
  exceeds its owner's role, and cannot reach credentials, sessions, the brand,
  or mint another token.
- An OpenAPI 3.1 description generated from the router. A route with no
  description fails a test by name, and so does a description left behind, so
  it cannot drift.
- Signed webhooks: HMAC-SHA256 over `<timestamp>.<body>`, with the timestamp
  inside the signed string so a recorded delivery cannot be replayed. Queued
  in the database and retried on a fixed backoff, which means a restart loses
  nothing and a cluster delivers once rather than once per node. Endpoints
  live in `peek.toml` and nowhere else, so there is no request-forgery vector
  to filter.
- OpenID Connect single sign-on: authorization code with PKCE, provisioning on
  first sign-in, directory groups mapped to roles, and `sso.required` enforced
  in the accounts service rather than by hiding a form. About six hundred lines
  with no dependency outside the standard library, and a closed algorithm
  table that contains no symmetric entry at all.

### Added — milestone M9, high availability and multi-organisation
- Several nodes behind a load balancer, sharing PostgreSQL and blob storage.
  Forty simultaneous reveals of a one-view secret across two nodes: one
  reader, thirty-nine answers indistinguishable from a link that never
  existed.
- Multi-organisation mode: one installation, several customers, each with its
  own brand, users, policies and audit trail, selected by the Host header.
- Domains proved by a DNS TXT record before they resolve, so nobody can point
  a name at an instance and wear another customer's brand. A domain proved
  once stays proved through a later DNS outage.
- `platform_admin`, the role above `admin`, for the person who onboards a
  customer rather than administers one.
- `docs/HIGH-AVAILABILITY.md`.

### Added — milestone M10, hardening, accessibility, performance
- Eighteen accessibility tests against the running binary: axe-core over
  WCAG 2.0, 2.1 and 2.2 at A and AA on every page in light and dark, plus the
  keyboard-only creation flow, a visible focus indicator, the skip link and an
  error that announces itself in a live region.
- Size budgets measured in CI (`make budget`): binary 28.7 MB of 60, recipient
  page 131.2 kB of 150 gzipped.
- Crypto benchmarks (`make bench`) and `docs/PERFORMANCE.md` with a load test:
  372 creations and 372 reveals a second on the default SQLite deployment, on
  one vCPU, with no errors and 31 MB of memory.

### Fixed
- A configuration error echoed the surrounding file, which put a webhook
  secret — and would have put `mail.password` or `sso.client_secret` — into
  journald, four times a second, while the service was in a restart loop. The
  message now names the setting and the line and nothing else.
- The Go toolchain was pinned to the minor version, so 1.26.7 shipped with
  twelve reachable standard-library advisories: nine in `net/http`, one each in
  `crypto/tls`, `crypto/x509` and `mime/multipart`. Pinned to the patch level.
- A webhook URL carried the receiver's query-string token out through
  `GET /api/v1/webhooks`, which an `instance:read` token can read.
- Unlinking a directory identity did not check the organisation, so a manager
  of one customer could unlink an account belonging to another.
- Adding `platform_admin` to the role ladder turned three hand-written
  `admin` checks into escalations — an administrator could have granted the
  role above their own. They are one function that reads the ladder.
- `peek org create acme --config …` ignored the flag: Go's flag package stops
  at the first non-flag argument, so the command loaded the wrong file and
  reported the wrong thing.
- Segmented controls cross-faded their background while the text colour
  changed with the state, passing through roughly 1.3:1 for a few frames in
  both directions.
- An SSO sign-in on another organisation's address produced a session that
  every later call refused; it is refused at the callback instead.
- An invited account signing in through the directory stayed "invited" for
  ever.

### Found by running it, not by reading it
- The service ran `/usr/bin/peek` while the shell ran a newer
  `/usr/local/bin/peek`, which turned a valid configuration into a restart
  loop with nothing in the obvious places to explain it. `peek doctor` now
  fails when the two differ.
- The SSO flow cookie was cleared in a `defer`, after `http.Redirect` had
  already written the header, so it stayed in the browser and the attempt
  remained replayable for its whole fifteen minutes.
- The tracking page for a secret request forgot an answer at the moment it
  displayed it: reading a deposit consumes it, so the next refresh dropped it.
- The API token separator was `_`, which is in the base64url alphabet, so one
  identifier in eight split in the wrong place and the token silently did not
  work.
- Two test harnesses shared one in-memory SQLite database, because the name
  came from the nanosecond clock and the DSN carries `cache=shared`.
- Raising a rate limit does not top an exhausted bucket back up; it refills
  from where it is.
- The RPM scriptlet died on its first line on RHEL — it was a copy of the
  Debian one — and CI had been creating the account by hand, hiding it.

### Changed
- `peek doctor` now also checks the installed binary, file storage, single
  sign-on reachability and the webhook queue, and prints the exact redirect URI
  to register at the identity provider.

### Added — milestone M0, foundations
- Single Go binary serving an embedded React interface (`go:embed`), with no
  runtime dependency and nothing loaded from a CDN.
- TOML configuration with strict validation, readable durations (`30m`, `7d`)
  and environment overrides for packaging.
- Structured JSON logging on stdout for journald; secrets, keys, passphrases
  and URL fragments are never logged.
- `/healthz` and `/readyz` probes for load balancers.
- Makefile, golangci-lint and ESLint configuration, GitHub Actions CI.

### Added — milestone M1, cryptographic core
- Zero-knowledge format v1: AES-256-GCM, per-secret 256-bit key, HKDF-SHA256,
  optional Argon2id passphrase stretching, proof of possession before reveal.
- Reference implementations in Go (`internal/crypto`) and TypeScript
  (`web/src/crypto`), pinned together by shared test vectors
  (`crypto/vectors/v1.json`) that both must reproduce byte for byte.
- `docs/CRYPTO.md` describing the format and its guarantees.

### Added — milestone M2, text secrets
- Create, share, reveal and burn text and URL secrets, encrypted in the browser.
- Expiry by duration and by number of reads, enforced atomically: fifty
  concurrent reads of a one-read secret yield exactly one success.
- Click-to-reveal step so link-preview bots consume no read.
- Optional passphrase with a bounded number of attempts; a wrong attempt costs
  no read, and exhausting the budget destroys the secret.
- Sender receipt page with live status, QR code and "destroy now".
- Real deletion on expiry or last read, with a per-minute purge job.
- Append-only audit trail that never records secret content.
- Rate limiting per real client IP, strict CSP, `no-store` on everything that
  touches a secret, `noindex` and `robots.txt`.
- Password generator with uniform sampling and an entropy estimate.
- French and English interface, light and dark themes, white-label colours.

### Added — milestone M3, operations
- `peek setup`, `peek doctor [--external]`, `peek config`, `peek migrate`,
  `peek backup` / `peek restore` (age-encrypted archives), `peek update` with
  checksum and minisign verification, automatic backup and automatic rollback,
  `peek rollback`, `peek key rotate`, `peek branding export|import`.
- Hardened systemd units, Debian and RPM packaging with maintainer scripts,
  `install.sh`, GoReleaser configuration producing signed `.tar.gz`, `.deb`
  and `.rpm` for amd64 and arm64, with checksums and an SBOM.

### Added — milestone M4, controlled exposure
- Two listeners: `public_listen` serves recipient routes only, `internal_listen`
  serves everything, so a load balancer can publish the first alone.
- `trusted_proxies`: forwarded headers (`X-Forwarded-For`, `Forwarded`,
  `X-Forwarded-Proto`, `X-Forwarded-Host`) are honoured only from declared
  proxies, and ignored everywhere else.
- PROXY protocol v1 and v2 for layer 4 load balancers.
- CIDR gates for administration and creation, answering 404 rather than 403.
- `/api/v1/ip` diagnostic endpoint and `peek doctor --external`.
- `docs/REVERSE-PROXY.md` with Kemp LoadMaster, HAProxy, nginx, F5, Apache and
  Traefik examples.

### Added — command line
- `peek-cli push` and `peek-cli get`: the same encryption as the browser, so a
  secret created in a terminal opens in a browser and the other way round.

### Found by running it, not by reading it
- The interface detects a non-secure context and explains that HTTPS is
  required, instead of failing with a raw `crypto.subtle is undefined` error.
  Browsers only expose WebCrypto over HTTPS or on localhost.
- `peek setup` hands the configuration to `root:peek 0640` and the master key
  to `peek:peek 0400`, so the service can read what it was just given; a
  permission error now prints the `chown` that fixes it.
- Administration commands run with `sudo` no longer leave root-owned SQLite
  files behind, and `peek doctor` does not create a database on a fresh
  install.
- `peek setup` enables the daily backup timer and waits for the service to
  answer before printing its diagnosis.
- The CSP carries `'wasm-unsafe-eval'`, without which the Argon2id WebAssembly
  module cannot run at all.

### Not yet implemented
Nothing. Milestones M5 to M10 are in the 1.0.0 section above.
