# Configuration

Peek reads one TOML file, `/etc/peek/peek.toml` by default. `peek setup`
writes it; `PEEK_CONFIG` or `--config` points elsewhere.

```bash
peek config check      # validate, and print a summary
peek config show       # print the effective configuration, secrets redacted
```

An unknown key is an error, not a warning: a typo in a security setting must
never be ignored. Durations are written as `45s`, `30m`, `12h`, `7d`.

A reference file with every default lives at
`/usr/share/doc/peek/peek.toml.example`.

## Top level

| Key | Default | What it does |
|---|---|---|
| `public_url` | `http://localhost:8080` | The URL users type. Links, cookies, CSP and redirects derive from it. Must match what the proxy publishes. |
| `default_language` | `fr` | `fr` or `en`. The visitor's own choice is remembered locally. |
| `multi_org` | `false` | Several organisations on one instance (milestone M9). |
| `update_check` | `true` | Daily check for a new release. Set `false` on an air-gapped host. |
| `update_url` | empty | Internal mirror instead of GitHub releases. |
| `update_channel` | `stable` | `stable` or `beta`. |
| `master_key_file` | `/etc/peek/master.key` | 32 random bytes, mode 0400. Back it up separately. |
| `data_dir` | `/var/lib/peek` | Database, encrypted files, brand assets. |

## `[server]`

| Key | Default | What it does |
|---|---|---|
| `internal_listen` | `127.0.0.1:8080` | Serves everything: creation, dashboard, administration, API. |
| `public_listen` | empty | Serves **recipient routes only**. Publish this one through the load balancer. |
| `trusted_proxies` | `[]` | The only sources whose `X-Forwarded-*` and `Forwarded` headers are believed. Empty means never. |
| `proxy_protocol` | `false` | PROXY protocol v1/v2 for layer 4 load balancers. Requires `trusted_proxies`, and refuses to start without it. |
| `read_timeout` | `30s` | |
| `write_timeout` | `2m` | Raise it for large encrypted uploads. |
| `idle_timeout` | `1m30s` | |
| `shutdown_grace` | `20s` | How long in-flight requests get on shutdown. |
| `max_body_bytes` | `8388608` | Request body cap. |
| `max_header_bytes` | `1048576` | |

See [REVERSE-PROXY.md](REVERSE-PROXY.md) for how these combine.

## `[tls]`

| Key | Default | What it does |
|---|---|---|
| `mode` | `none` | `none` (terminated upstream), `file` (Peek terminates), `acme` (milestone M4, currently refuses). |
| `cert_file`, `key_file` | empty | Required for `file`. |
| `hsts` | `false` | Send `Strict-Transport-Security`. Leave off when the proxy already sends it. |
| `hsts_max_age` | `31536000` | |

## `[database]`

| Key | Default | What it does |
|---|---|---|
| `driver` | `sqlite` | `sqlite`, or `postgres` (milestone M9, currently refuses to start). |
| `dsn` | `/var/lib/peek/peek.db` | File path, or a PostgreSQL DSN. |

SQLite runs in WAL mode. For several nodes you need PostgreSQL: do not point
two instances at one SQLite file on NFS.

## `[storage]`

| Key | Default | What it does |
|---|---|---|
| `backend` | `local` | `local`, or `s3` (milestone M7). |
| `path` | `/var/lib/peek/files` | Encrypted blobs. May be a shared mount in HA. |

## `[security]`

| Key | Default | What it does |
|---|---|---|
| `admin_allowed_cidrs` | `[]` | Restricts administration, audit and policy routes to these networks. Answers 404 elsewhere. |
| `create_allowed_cidrs` | `[]` | Restricts secret creation. |
| `anonymous_create` | `false` | Allow creating without an account. Accounts arrive in M5; until then this is the switch that enables creation at all. |
| `max_passphrase_attempts` | `5` | Wrong attempts before the secret is destroyed. |
| `anonymize_ips` | `false` | Keep only a /24 (IPv4) or /48 (IPv6) prefix in logs and audit entries. |
| `audit_retention` | `365d` | `0` keeps the audit trail forever. |

### Rate limits

Four token buckets, each per real client IP: `rate_create`, `rate_read`,
`rate_login`, `rate_api`.

```toml
[security.rate_read]
burst  = 30      # immediate allowance; 0 disables the limit
rate   = 300     # sustained refill...
window = "1h"    # ...per this window
```

In-memory on a single node, which is the default deployment; shared through the
database in M9.

## `[policy]`

| Key | Default | What it does |
|---|---|---|
| `max_ttl` / `default_ttl` | `30d` / `1d` | Expiry ceiling and default. |
| `max_views` / `default_views` | `100` / `1` | Reads ceiling and default. |
| `require_passphrase` | `false` | Refuse creation without a passphrase. |
| `force_retrieval_step` | `false` | Force the click-to-reveal step. |
| `allowed_kinds` | `["text","url","file"]` | Kinds this instance accepts. |
| `max_file_bytes` | `104857600` | 100 MiB (milestone M7). |
| `max_secret_bytes` | `1048576` | Ciphertext cap for a text secret. |
| `max_recipients` | `10` | Multi-recipient links (milestone M7). |

## `[mail]`

Leave `host` empty to disable every e-mail feature.

| Key | Default | What it does |
|---|---|---|
| `host`, `port` | empty, `587` | SMTP server. |
| `username`, `password` | empty | Omit both for an anonymous internal relay. |
| `encryption` | `starttls` | `none`, `starttls` or `tls`. |
| `from_name`, `from_address` | `Peek`, empty | Sender identity. |
| `skip_tls_verify` | `false` | For an internal relay with a private CA. Prefer trusting the CA. |
| `allowed_recipient_domains` | `[]` | Restrict who a link may be e-mailed to. |

`peek doctor` connects, negotiates STARTTLS and authenticates, without sending
anything.

## `[log]`

| Key | Default | What it does |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn`, `error`. |
| `format` | `json` | `json` or `text`. |
| `file` | empty | Empty means stdout, captured by journald. Set a path for logrotate. |

Secrets, keys, passphrases, URL fragments and request bodies are never logged,
at any level. The access log records the matched route pattern, not the URL.

## `[branding]`

| Key | Default | What it does |
|---|---|---|
| `service_name` | `Peek` | Shown everywhere, including the tab title. |
| `primary_color`, `accent_color` | `#4f46e5`, `#0ea5e9` | A full palette is generated, with a WCAG AA contrast check that warns rather than silently correcting. |
| `hide_powered_by` | `false` | |
| `support_url`, `legal_url`, `privacy_url` | empty | Footer links. |

See [BRANDING.md](BRANDING.md).

## `[backup]`

| Key | Default | What it does |
|---|---|---|
| `enabled` | `true` | Used by the systemd timer. |
| `dir` | `/var/backups/peek` | |
| `keep` | `7` | Archives kept. An archive holds the ciphertext of active secrets: keep this small. |
| `passphrase` | empty | Set one: the archive is then encrypted with age. |
| `interval` | `1d` | |

## Environment overrides

For packaging and tests, not for secrets: `PEEK_CONFIG`, `PEEK_PUBLIC_URL`,
`PEEK_INTERNAL_LISTEN`, `PEEK_PUBLIC_LISTEN`, `PEEK_DB_DSN`, `PEEK_DATA_DIR`,
`PEEK_LOG_LEVEL`. `PEEK_UPDATE_TOKEN` is read by `peek update` for an
authenticated release mirror.

## Applying a change

```bash
sudo nano /etc/peek/peek.toml
sudo peek config check
sudo systemctl restart peek
sudo peek doctor
```
