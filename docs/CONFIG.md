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
| `backend` | `local` | `local`, or `s3`. |
| `path` | `/var/lib/peek/files` | Encrypted blobs, local backend. May be a shared mount in HA. |
| `s3_bucket` | — | Required for `s3`. |
| `s3_region` | `us-east-1` | Signing region. Most S3-compatible appliances accept anything consistent. |
| `s3_endpoint` | — | Full URL of the endpoint. Empty means AWS. |
| `s3_prefix` | — | Key prefix inside the bucket, letters, digits, `-`, `_`, `.` and `/`. |
| `s3_path_style` | implied | Bucket in the path rather than in the host name. Set automatically when `s3_endpoint` is given, because appliances rarely have a wildcard certificate. |
| `s3_access_key` / `s3_secret_key` | — | Credentials. The secret is redacted in `peek config show`. |

Peek signs S3 requests itself (SigV4) and uses `PUT`, `GET`, `HEAD`, `DELETE`
and `ListObjectsV2` — nothing else. There is no AWS SDK in the binary, which
also means **no credential chain**: the keys come from this file and nowhere
else, and nothing ever probes an instance-metadata endpoint. The reasoning is
in [DECISIONS.md](DECISIONS.md).

```toml
[storage]
backend       = "s3"
s3_bucket     = "peek-secrets"
s3_endpoint   = "https://minio.acme.internal:9000"
s3_region     = "eu-west-3"
s3_access_key = "…"
s3_secret_key = "…"
```

Whatever the backend, a blob is already encrypted when it arrives: the bucket
holds opaque streams and their lengths, and the keys are in payloads the server
cannot read.

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
| `max_file_bytes` | `104857600` | 100 MiB of plaintext per file. The accepted upload is a little larger: the chunked format adds a 17-byte header and 16 bytes per mebibyte. |
| `max_secret_bytes` | `1048576` | Ciphertext cap for a text secret. |
| `max_recipients` | `10` | Links per multi-recipient bundle. |
| `max_files_per_secret` | `10` | Attachments per bundle. |
| `upload_window` | `2h` | How long an uploaded blob waits for a secret to claim it. A sender who closes the tab leaves nothing behind for longer than this. |
| `download_window` | `30m` | How long a recipient keeps access to the attachments after revealing. The secret row is already gone by then; this is what lets a large download finish. |
| `max_deposits` | `1` | Answers a secret request may accept. |

Raising `download_window` keeps blobs on disk longer after they have been read;
lowering it can cut off a slow download of a large file. Thirty minutes is
roughly a 100 MiB file over a poor connection, with room to spare.

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

## Multi-organisation mode

```toml
multi_org = true
```

Off by default, and off is the right answer for almost every installation:
one instance, one customer, `public_url` in this file and nothing else to
think about.

Turn it on and one installation hosts several organisations. Each gets its own
brand, users, policies, secrets and audit trail, and the **Host header** says
which one a request belongs to.

That header is attacker-controlled on a direct connection, so two things make
it safe to act on:

- it is read from `X-Forwarded-Host` only when the peer is in
  `server.trusted_proxies`, and from the connection otherwise — the same rule
  the real-client-IP code follows;
- a domain resolves to nothing until a **DNS TXT record** has proved it.
  Without the proof, anyone able to point a name at this instance could wear
  another customer's brand, and a recipient would see the right logo above the
  wrong organisation's page.

### Setting one up

```bash
sudo peek org create acme --name "ACME Ltd"
sudo peek org domain-add secrets.acme.com --slug acme
# publish the TXT record it prints, then:
sudo peek org domain-verify secrets.acme.com
```

The record is
`_peek-challenge.secrets.acme.com. IN TXT "peek-verification=<token>"`. A
dedicated label rather than the apex, because an apex TXT record is shared
with SPF, DMARC and half a dozen other verification tokens, and operators
delete each other's.

The verification lookup is **the only outbound DNS query Peek makes**, and it
happens because somebody asked for it. Nothing is resolved on a recipient's
request path, so an air-gapped instance never reaches it.

A domain proved once stays proved: a later failed re-check records what the
resolver saw and leaves `verified_at` alone. Taking a customer's brand away
because their registrar was slow would be the wrong failure.

### What changes

| | Single-tenant | Multi-organisation |
|---|---|---|
| Brand | `public_url`, one brand | resolved per verified domain |
| Links | built on `public_url` | built on that organisation's primary domain |
| E-mails | the instance brand | the organisation's brand |
| Accounts | one pool | one pool per organisation, `(org_id, email)` unique |
| Roles | `admin` at the top | `platform_admin` above it |
| Interface | the notion is hidden | an Organisations tab, for `platform_admin` only |

The first domain an organisation verifies also becomes its **primary** one —
the origin its links are built on — so the address in a link, the certificate
serving it and the brand on the page all agree. Change it with
`peek org domain-primary`.

A **suspended** organisation keeps every row and stops resolving: a customer
who has not paid is not a customer whose secrets are deleted.

### The platform role

`platform_admin` sits above `admin` and is the only role that may create an
organisation or touch a domain. On a hosted instance the person who onboards a
customer is not the person who administers that customer, and an administrator
of one organisation must not be able to see the others exist.

```bash
sudo peek admin set-role --email ops@example.com --role platform_admin
```

No role can grant a role above its own, which is checked once in the accounts
service rather than per call site.

## `[sso]`

OpenID Connect single sign-on. One provider per instance: an instance belongs
to one organisation with one directory, and two providers would mean two
sources of truth for who somebody is.

```toml
[sso]
enabled       = true
provider      = "entra"
issuer        = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
client_id     = "11111111-1111-1111-1111-111111111111"
client_secret = "…"
scopes        = ["openid", "profile", "email"]

provision     = true
default_role  = "member"
groups_claim  = "groups"
admin_groups  = ["3f6c…"]      # Entra sends object ids, not names
manager_groups = ["a91b…"]
sync_role_on_login = true
```

| Key | Default | What it does |
|---|---|---|
| `enabled` | `false` | |
| `provider` | `generic` | `entra`, `google`, `keycloak`, `authentik`, `adfs` or `generic`. It only picks the button label and shapes the error messages; the protocol is the same. |
| `display_name` | from `provider` | What the sign-in button says. |
| `issuer` | required | Must be `https`, and must equal the `iss` claim of every token exactly. |
| `client_id`, `client_secret` | required | Peek authenticates to the token endpoint as a confidential client. |
| `scopes` | `["openid","profile","email"]` | Add whatever your provider needs asked for to send groups. |
| `discovery` | `true` | Reads `<issuer>/.well-known/openid-configuration`. |
| `authorize_url`, `token_url`, `jwks_url`, `userinfo_url` | empty | Required when `discovery = false`. |
| `ca_file` | empty | Pin the provider's authority, for an internal Keycloak or ADFS. |
| `required` | `false` | Refuses **every** local credential, password and passkey alike. Not merely hides the form. |
| `password_exempt` | `[]` | The addresses that may still sign in locally when `required` is set. |
| `provision` | `true` | Create an account on first sign-in. Off means only existing accounts may sign in. |
| `default_role` | `member` | For a user whose groups match nothing. |
| `allowed_domains` | `[]` | Bare domains, e.g. `["acme.com"]`. Empty means any domain the provider vouches for. |
| `groups_claim` | `groups` | `roles` for an Entra app-role registration. |
| `admin_groups`, `manager_groups`, `auditor_groups`, `member_groups` | `[]` | A user in several gets the **strongest** role. |
| `require_group` | `false` | Refuse anyone whose groups match none of the maps. |
| `sync_role_on_login` | `true` | Re-apply the mapping at every sign-in, so a change in the directory takes effect without touching Peek. Off means the role is set at creation and local edits stick. |

### Register this redirect URI

```
<public_url>/auth/sso/callback
```

Character for character. It is fixed — a configurable callback path is a
configurable open redirect waiting to be mistyped — and `peek doctor` prints
the exact value to paste into the application at the provider.

### `required`, and why the escape hatch is explicit

`sso.required` refuses local credentials on the server, not in the interface.
That means an instance whose provider is unreachable — an outage, an expired
client secret, a network change — is an instance nobody can sign in to, with
the configuration file that would fix it readable only by root.

So the escape hatch is named rather than implied. There is no hidden exception
for administrators: put one or two break-glass accounts in
`sso.password_exempt`, give them a second factor, and audit them.
`peek doctor` **fails** when `required` is set and the list is empty.

### Accounts, and what links them

An account is linked to a directory identity by `(issuer, subject)`, never by
the e-mail address. An address is a label that changes; a subject is the
directory's own identifier and does not. So a renamed mailbox follows the
person, and a reassigned one does not become a way into their account.

On a first sign-in, in this order:

1. the e-mail domain is checked against `allowed_domains`;
2. an account with that `(issuer, subject)` is looked for;
3. then an account with that address — linking it requires that account to be
   unlinked, and the provider not to have marked the address unverified;
4. and only then, if `provision` is on, a new account is created with no
   password hash at all.

An administrator can detach an identity from an account
(`DELETE /api/v1/users/{id}/sso`), which is the way out of a subject linked to
the wrong account.

### Entra ID: the group overflow

Past roughly two hundred groups, Entra replaces the group list in the token
with a pointer to Microsoft Graph. Peek will not call Graph — that is a second
outbound dependency and a second credential — so it **refuses the sign-in and
says so** rather than seeing no groups and handing out `default_role`, which
would quietly demote an administrator.

Use app roles instead (`groups_claim = "roles"`), or set a group filter in the
application registration so only the relevant groups are sent.

## `[[webhook]]`

Repeated. Each table declares one outbound endpoint.

```toml
[[webhook]]
name    = "siem"
url     = "https://hooks.example.com/peek"
secret  = "a long random string, 16 characters minimum"
events  = ["secret.revealed", "secret.expired", "secret.burned", "request.deposited"]

[[webhook]]
name     = "chat"
url      = "http://mattermost.internal/hooks/xxxx"
secret   = "another long random string"
events   = ["*"]
ca_file  = "/etc/ssl/certs/internal-ca.pem"
```

| Key | Default | What it does |
|---|---|---|
| `name` | required | How the queue, the logs and `peek webhook` refer to it. Change the URL and the queued events survive. |
| `url` | required | `http` or `https`. |
| `secret` | required, 16 characters minimum | The HMAC-SHA256 key the receiver verifies. An unsigned webhook is a notification anybody who can reach the receiver can forge. |
| `events` | the four below | Audit event names, or `["*"]` for the whole trail. |
| `max_attempts` | `6` | Counts the first try. |
| `timeout` | `10s` | Per attempt. |
| `disabled` | `false` | Keeps the declaration while silencing it. |
| `skip_tls_verify` | `false` | A real downgrade: the signature proves who sent the body, not who read it. Prefer `ca_file`. |
| `ca_file` | empty | Pin the receiver's authority. The right answer on an internal network. |

The default subscription is the sender-facing lifecycle:
`secret.revealed`, `secret.expired`, `secret.burned`, `request.deposited`.

There is no API call that creates an endpoint, and there never will be: a URL
a caller could set would make Peek fetch on their behalf, from inside the
network they cannot reach. Endpoints live in this file.

The body of a delivery is an audit entry. That trail is built never to contain
a secret, a key, a passphrase or a URL fragment, so forwarding it is safe by
construction — but it does carry identifiers and sometimes an e-mail address.
Point a webhook somewhere you would be happy to see the audit trail.

`docs/API.md` has the signature scheme and a receiver in twenty lines.
`peek webhook list|test|queue|retry` inspects it from the host, and
`peek doctor` warns when the queue stops draining.

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
