# Peek

**Ephemeral secret sharing, self-hosted, white-label.**
One Linux binary, systemd, no Docker, no runtime to install, nothing loaded
from the internet by the browser.

A secret is encrypted **in the sender's browser**. The server stores a
ciphertext and two digests. The key travels in the URL fragment, which browsers
never send. Peek cannot read what it holds — by construction, not by policy.

```
┌── sender's browser ─────────┐        ┌── peek ──────────────┐
│ AES-256-GCM + HKDF          │ POST   │ ciphertext           │
│ (+ Argon2id if passphrase)  │ ─────► │ SHA-256(read token)  │
│ key stays in the fragment   │        │ expiry, read counter │
└─────────────────────────────┘        └──────────────────────┘
          │  https://secrets.acme.com/s/<id>#<key>
          ▼
┌── recipient's browser ──────┐  proof of possession, then one read is spent
│ derives the read token      │ ─────► ciphertext ─────► decrypted locally
└─────────────────────────────┘
```

## What works today

| Area | State |
|---|---|
| Text and URL secrets, encrypted end to end | ✅ |
| Expiry by duration **and** by number of reads, enforced atomically | ✅ |
| Click-to-reveal step: preview bots spend no read | ✅ |
| Optional passphrase, bounded attempts, secret destroyed on exhaustion | ✅ |
| Sender receipt page: live status, QR code, destroy now | ✅ |
| Recipient deletion, real deletion on expiry, per-minute purge | ✅ |
| Append-only audit trail with no secret content | ✅ |
| Rate limiting, strict CSP, `no-store`, `noindex` | ✅ |
| White-label name, colours and generated palette with contrast checks | ✅ |
| French and English, light and dark themes | ✅ |
| Two listeners: expose recipient pages only | ✅ |
| Real client IP behind Kemp, F5, HAProxy, nginx (+ PROXY protocol) | ✅ |
| `setup`, `doctor`, `backup`, `restore`, signed `update` with rollback | ✅ |
| `.deb`, `.rpm`, `.tar.gz`, hardened systemd units, `install.sh` | ✅ |
| `peek-cli push` / `get`, byte-compatible with the browser | ✅ |
| Accounts, roles, SSO, TOTP, passkeys | milestone M5 |
| Branding editor with live preview, branded e-mails | milestone M6 |
| Files, multi-recipient, secret requests, S3 | milestone M7 |
| Documented REST API, tokens, webhooks | milestone M8 |
| PostgreSQL, high availability, multi-organisation | milestone M9 |

Unfinished areas fail loudly rather than pretending: setting
`database.driver = "postgres"` or `tls.mode = "acme"` refuses to start with an
explanation instead of silently doing something else.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh | sudo sh
```

or, from a downloaded package:

```bash
sudo apt install ./peek_1.0.0_linux_amd64.deb   # Debian, Ubuntu
sudo dnf install ./peek-1.0.0.amd64.rpm         # RHEL, Rocky, Alma
sudo peek setup
```

`peek setup` asks for the public URL, the exposure mode, the listeners, TLS,
the database and SMTP, writes `/etc/peek/peek.toml`, generates the master key,
creates the service account and directories, starts the service and finishes
with a `peek doctor`.

Full instructions: [docs/INSTALL.md](docs/INSTALL.md).

## Upgrade

```bash
sudo peek update              # checks the signature, backs up, swaps, verifies, rolls back on failure
sudo peek update --check      # exit code 10 when a release is available
sudo peek update --file peek_1.4.2_linux_amd64.tar.gz   # offline host
sudo peek rollback
```

Details: [docs/UPGRADE.md](docs/UPGRADE.md).

## HTTPS is required

Encryption happens in the browser, and browsers only expose WebCrypto over
`https://` or on `localhost`. An instance published over plain HTTP on a LAN
address will load, state the problem plainly, and refuse to encrypt. Terminate
TLS on your proxy, or set `tls.mode = "file"`.

## Expose it safely

Peek is built to sit behind a load balancer with only its recipient pages
published:

```toml
[server]
internal_listen = "10.0.0.5:8080"   # creation, dashboard, administration, API
public_listen   = "10.0.0.5:8081"   # recipient pages only — publish this one
trusted_proxies = ["10.0.0.0/24"]   # the only sources whose X-Forwarded-* is believed
```

Ready-made configurations for Kemp LoadMaster, HAProxy, nginx, F5, Apache and
Traefik: [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md).
Then check it from the server itself:

```bash
sudo peek doctor --external
```

It reports the client IP Peek actually resolves, the certificate, and whether
the admin surface answers through the public URL — the mistake that matters.

## Build from source

Requires Go 1.26+ and Node 22+. No Docker.

```bash
make deps
make build        # builds the interface, embeds it, produces bin/peek
make test         # Go tests with -race, TypeScript tests, shared crypto vectors
make lint
./bin/peek version
```

Development loop (API on :8080, Vite on :5173):

```bash
make dev-config
make dev
```

## Documentation

| Document | Contents |
|---|---|
| [INSTALL.md](docs/INSTALL.md) | Installation, service account, first run |
| [CONFIG.md](docs/CONFIG.md) | Every setting in `peek.toml` |
| [REVERSE-PROXY.md](docs/REVERSE-PROXY.md) | Kemp, HAProxy, nginx, F5, Apache, Traefik, direct TLS |
| [UPGRADE.md](docs/UPGRADE.md) | Updates, offline updates, rollback |
| [BACKUP.md](docs/BACKUP.md) | Backups, restore, what an archive contains |
| [CRYPTO.md](docs/CRYPTO.md) | The v1 format, key derivation, test vectors |
| [THREAT-MODEL.md](docs/THREAT-MODEL.md) | What zero-knowledge protects, and what it does not |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Code layout and request flow |
| [BRANDING.md](docs/BRANDING.md) | White-labelling an instance |
| [API.md](docs/API.md) | HTTP endpoints as implemented today |
| [DECISIONS.md](docs/DECISIONS.md) | Decisions taken, with their reasons |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

## Licence

Proprietary. See [LICENSE](LICENSE).
