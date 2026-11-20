# Changelog

All notable changes to Peek are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Not yet implemented
Accounts, roles, SSO and TOTP (M5); the branding editor with live preview and
branded e-mails (M6); files, multi-recipient and secret requests (M7); the
documented REST API, tokens and webhooks (M8); PostgreSQL, HA and multi-org
(M9). The configuration and the data model already carry their fields, and the
server refuses loudly rather than pretending to support them.
