# Installing Peek

Peek is a single static Linux binary driven by systemd. There is no Docker, no
runtime to install, no application server and no asset directory to deploy.

Tested on **Debian 12 and 13, Ubuntu 22.04 and 24.04, RHEL / Rocky / Alma 9**,
on **amd64 and arm64**.

## Requirements

| Item | Minimum | Comfortable |
|---|---|---|
| CPU | 1 core | 2 cores |
| RAM | 256 MB | 512 MB |
| Disk | 1 GB | 10 GB (file attachments, backups) |
| Network | one TCP port | two (recipient and internal) |

SQLite is the default database and needs nothing installed.

## 1. Install the package

### Debian, Ubuntu

```bash
sudo apt install ./peek_1.0.0_linux_amd64.deb
```

### RHEL, Rocky, Alma

```bash
sudo dnf install ./peek-1.0.0.amd64.rpm
```

### Script

```bash
curl -fsSL https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh | sudo sh
```

The script detects the distribution and the architecture, downloads the right
package, verifies its SHA-256 against `checksums.txt`, and — when you pass
`--pubkey` and have `minisign` installed — verifies the release signature
before installing anything.

To read it before running it, which is the right habit:

```bash
curl -fsSLO https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh
less install.sh
sudo sh install.sh --pubkey "RWQ…"
```

### Archive, no package manager

```bash
tar xzf peek_1.0.0_linux_amd64.tar.gz
sudo install -m 0755 peek /usr/bin/peek
sudo install -m 0644 packaging/systemd/peek.service /usr/lib/systemd/system/
sudo install -m 0644 packaging/systemd/peek-backup.service /usr/lib/systemd/system/
sudo install -m 0644 packaging/systemd/peek-backup.timer /usr/lib/systemd/system/
sudo useradd --system --home-dir /var/lib/peek --no-create-home --shell /sbin/nologin peek
sudo install -d -o peek -g peek -m 0750 /var/lib/peek /var/backups/peek
sudo systemctl daemon-reload
sudo peek setup
```

What the package installs:

```
/usr/bin/peek                              the binary (server + admin commands)
/usr/lib/systemd/system/peek.service       hardened service unit
/usr/lib/systemd/system/peek-backup.*      daily backup service and timer
/usr/share/doc/peek/peek.toml.example      reference configuration
/var/lib/peek/                             database, encrypted files, assets
/var/backups/peek/                         local backups
```

The package creates the `peek` system account (no shell, no home) and the
directories with the right ownership. It never starts the service before you
have run `peek setup`.

## 2. Run the assistant

```bash
sudo peek setup
```

It asks for:

- the service name shown to users, the public URL and the default language;
- the exposure mode — `internal` (LAN only), `proxy` (behind Kemp, F5, HAProxy,
  nginx…) or `direct` (Peek terminates TLS);
- the listeners: `internal_listen` serves everything, and in `proxy` mode you
  are offered a second `public_listen` that serves **only** the recipient
  pages, so the load balancer can publish that one alone;
- the addresses of your load balancers, which become `trusted_proxies` — the
  only sources whose `X-Forwarded-*` headers Peek will believe;
- TLS: none, or a certificate and key file;
- the database (SQLite file or a PostgreSQL DSN) and the data directory;
- SMTP, if you want e-mail;
- whether secrets may be created without an account.

It then writes `/etc/peek/peek.toml` (mode 0640, keeping a `.bak` of any
previous one), generates `/etc/peek/master.key` (32 random bytes, mode 0400),
creates and chowns the directories, offers to enable and start the service, and
finishes by running `peek doctor`.

Scripted installs take the same answers as flags:

```bash
sudo peek setup --non-interactive --force \
  --service-name "Coffre ACME" \
  --public-url https://secrets.acme.com \
  --mode proxy \
  --internal-listen 10.0.0.5:8080 \
  --public-listen 10.0.0.5:8081 \
  --trusted-proxies 10.0.0.10/32,10.0.0.11/32 \
  --db sqlite --dsn /var/lib/peek/peek.db \
  --anonymous-create
```

## 3. Check it

```bash
sudo peek doctor
```

It inspects the configuration and its permissions, the master key, every
directory and its free space, the database and its migrations, both listeners,
the proxy trust settings, TLS and certificate expiry, the clock and SMTP. Each
line is `OK`, `WARN`, `FAIL` or `SKIP`, with the command that fixes it. The
exit code is non-zero if anything failed, so it drops straight into Ansible or
a monitoring check (`--json` gives machine-readable output).

Once it is published through your load balancer:

```bash
sudo peek doctor --external
```

This additionally checks the public URL, the certificate chain, which client IP
Peek resolves through the proxy, and whether the admin surface is reachable
from outside.

## 4. Service management

```bash
sudo systemctl status peek
sudo systemctl restart peek
sudo journalctl -u peek -f            # structured JSON logs
sudo systemctl list-timers peek-backup.timer
```

Check the hardening of the unit:

```bash
systemd-analyze security peek
```

## 5. First use

Open the public URL. Accounts, roles and SSO arrive in milestone M5; until
then, creation is controlled by two settings:

```toml
[security]
anonymous_create     = true               # off by default
create_allowed_cidrs = ["10.0.0.0/8"]     # and optionally restrict who
```

Recipients never need either: a link plus, where applicable, the passphrase is
all it takes.

## 6. Uninstall

```bash
sudo apt remove peek        # or: sudo dnf remove peek
```

Removal deliberately keeps `/etc/peek` (configuration and master key),
`/var/lib/peek` (database and encrypted blobs) and `/var/backups/peek`. Delete
them by hand if you really mean to — without `master.key`, encrypted metadata
in a backup is unrecoverable.

## Troubleshooting

| Symptom | Where to look |
|---|---|
| Service will not start | `journalctl -u peek -n 50`, then `peek config check` |
| "unknown setting" at startup | a typo in `peek.toml`; the message names the key |
| Browser shows "interface not compiled" | binary built without `make web-build` |
| Secrets always say "no longer valid" | check the clock: `peek doctor` reports it |
| Peek sees the proxy IP as the client | `trusted_proxies`, and the proxy must send `X-Forwarded-For` — see [REVERSE-PROXY.md](REVERSE-PROXY.md) |
| Permission denied on `/var/lib/peek` | `sudo chown -R peek:peek /var/lib/peek` |
| Passphrase step fails in the browser | an upstream proxy is rewriting the CSP; `script-src` must keep `'wasm-unsafe-eval'` for Argon2id |
