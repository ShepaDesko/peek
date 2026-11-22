# HTTP API

This describes the endpoints **as implemented today**. The documented, stable
`/api/v1` with an OpenAPI 3.1 document, scoped tokens and webhooks is milestone
M8; what is below is what the interface and `peek-cli` use, and it is already
stable enough to script against.

All bodies are JSON. All byte strings are **base64url, unpadded**. Everything
under `/api/v1` is served with `Cache-Control: no-store`.

## Where an endpoint is served

| Endpoint | Public listener | Internal listener |
|---|---|---|
| `GET /healthz`, `GET /readyz` | yes | yes |
| `GET /api/v1/branding`, `GET /branding.css` | yes | yes |
| `GET /api/v1/ip` | yes | yes |
| `GET /api/v1/secrets/{id}` | yes | yes |
| `POST /api/v1/secrets/{id}/reveal` | yes | yes |
| `DELETE /api/v1/secrets/{id}` | yes | yes |
| `GET /api/v1/files/{id}` | yes | yes |
| `GET /api/v1/requests/{id}` | yes | yes |
| `POST /api/v1/requests/{id}/open` | yes | yes |
| `POST /api/v1/requests/{id}/deposit` | yes | yes |
| `POST /api/v1/secrets` | **no** | yes |
| `POST /api/v1/files` | **no** | yes |
| `POST /api/v1/requests` | **no** | yes |
| `GET /api/v1/secrets/{id}/receipt` | **no** | yes |
| `POST /api/v1/secrets/{id}/burn` | **no** | yes |
| `POST /api/v1/requests/{id}/receipt`, `DELETE /api/v1/requests/{id}` | **no** | yes |
| `GET /api/v1/policy`, `/api/v1/audit`, `/api/v1/instance` | **no** | yes |

Uploading sits behind the creation gate, not the read one: an instance that
does not let you create a secret is not a place to drop a hundred megabytes
either. Downloading is recipient-facing, but needs a grant that only a
successful reveal hands out.

"Public listener" means the one configured as `server.public_listen`. With a
single listener, everything is served there, and `security.admin_allowed_cidrs`
is what restricts the admin surface.

## Errors

```json
{ "error": { "code": "policy", "message": "views: 50 views requested, the limit is 10", "field": "views" } }
```

| Status | Code | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed body, unknown field, bad base64 |
| 403 | `bad_token` | Wrong read token or passphrase; carries `attempts_left` |
| 403 | `creation_disabled` | `security.anonymous_create` is false |
| 404 | `not_found` | Unknown, expired, consumed or burned — deliberately indistinguishable |
| 409 | `conflict` | Identifier already used |
| 410 | `locked` | Too many failed attempts; the secret was destroyed |
| 422 | `policy` | Refused by instance policy; `field` names the setting |
| 429 | `rate_limited` | Token bucket exhausted; see `Retry-After` |
| 411 | `length_required` | An upload arrived without `Content-Length` |
| 413 | `too_large` | File beyond `policy.max_file_bytes` |
| 410 | `closed` | A secret request has had all the answers it accepts |
| 503 | `no_storage` | No file storage configured on this instance |
| 401 | `bad_api_token` | Unknown, revoked or expired API token |
| 403 | `missing_scope` | The token does not carry the scope this call needs |
| 403 | `session_required` | The call needs a session, not a token |

## Authenticating as a script

Two ways in. The interface uses a session cookie plus a double-submit CSRF
header; a script uses a **bearer token**:

```http
Authorization: Bearer peek_<id>.<secret>
```

The `peek_` prefix is there so secret scanners recognise one on sight. A token
sends no cookie, so no CSRF header is needed or wanted.

A token belongs to a user and **can never exceed that user's role** — it
narrows it. On top of the role it carries scopes:

| Scope | What it opens |
|---|---|
| `secrets:write` | `POST /secrets`, `POST /files`, `POST /requests` |
| `secrets:manage` | receipts, `burn`, `email`, request receipts, closing a request |
| `audit:read` | `GET /audit`, `GET /audit/export` |
| `instance:read` | `GET /instance` |

Everything else is closed to a token, whatever its scopes: changing a password,
listing sessions, managing users, editing the brand — and creating another
token. One leaked string must not become a key factory.

| Status | Code | Meaning |
|---|---|---|
| 401 | `bad_api_token` | Unknown, revoked or expired — one answer for all three |
| 403 | `missing_scope` | Valid token, but not for this call |
| 403 | `session_required` | This call needs a signed-in person |

### Managing tokens

From the account page, or from the shell on the server:

```bash
sudo peek token create --email ops@acme.com --name "CI" --scopes secrets:write --ttl 90d
sudo peek token list --all
sudo peek token revoke --id <id>
```

Over HTTP (session only, never with a token):

```http
GET    /api/v1/auth/tokens
POST   /api/v1/auth/tokens      { "name": "CI", "scopes": ["secrets:write"], "ttl_seconds": 7776000 }
DELETE /api/v1/auth/tokens/{id}
```

The creation response is the **only** place the clear text ever appears; the
database holds its SHA-256. Revoking is a timestamp, not a deletion, so an
audit entry that names a token can still be read. An administrator may revoke
anyone's token — a colleague leaves, their scripts stop.

```bash
TOKEN=peek_...
curl -sS -H "Authorization: Bearer $TOKEN" https://secrets.acme.com/api/v1/policy
```

## Health

```http
GET /healthz   →  200  "ok"
GET /readyz    →  200  {"ready":true,"checks":[{"name":"database","ok":true}]}
               →  503  when a check fails
```

Point your load balancer at `/readyz`.

## Diagnostics

```http
GET /api/v1/ip
```

```json
{ "client_ip": "203.0.113.5", "peer_addr": "10.0.0.10:52118",
  "scheme": "https", "host": "secrets.acme.com",
  "listener": "public", "trusted_peer": true }
```

This is the fastest way to find out whether your proxy configuration works.

## Branding

```http
GET /api/v1/branding        → the theme as JSON, with an ETag
GET /branding.css           → the same theme as CSS custom properties
```

Both support `If-None-Match` and answer 304.

## Policy

```http
GET /api/v1/policy
```

Returns the limits the interface must respect: maximum TTL and reads, whether a
passphrase is required, allowed kinds, size limits and the KDF parameters to
use. Internal listener only.

## Creating a secret

```http
POST /api/v1/secrets
Content-Type: application/json
```

```json
{
  "id": "4C8Wft7uBQb8G-tWya6P2g",
  "kind": "text",
  "ciphertext": "<base64url(nonce || AES-256-GCM)>",
  "read_token_hash": "<base64url(SHA-256(read token))>",
  "receipt_token_hash": "<base64url(SHA-256(receipt token))>",
  "kdf": { "salt": "<base64url(16 B)>", "memory_kib": 19456, "iterations": 2, "parallelism": 1 },
  "has_passphrase": false,
  "ttl_seconds": 86400,
  "views": 1,
  "retrieval_step": true,
  "deletable_by_recipient": false
}
```

The identifier, the key, the salt and both tokens are generated by the client.
The server sees no key and no passphrase. Response:

```json
{ "id": "4C8Wft7uBQb8G-tWya6P2g", "kind": "text", "views_max": 1,
  "expires_at": "2026-11-21T14:43:45Z", "created_at": "2026-11-20T14:43:45Z",
  "url": "https://secrets.acme.com/s/4C8Wft7uBQb8G-tWya6P2g" }
```

The link the recipient needs is `url` plus `#v1.<base64url(content key)>`,
assembled by the client.

## Reading metadata

```http
GET /api/v1/secrets/{id}
```

```json
{ "id": "…", "kind": "text", "has_passphrase": true, "retrieval_step": true,
  "deletable_by_recipient": false, "views_remaining": 1, "views_max": 1,
  "expires_at": "2026-11-21T14:43:45Z", "size_bytes": 108, "attempts_left": 5,
  "kdf": { "salt": "…", "memory_kib": 19456, "iterations": 2, "parallelism": 1 } }
```

**No read is consumed.** This is what makes link-preview bots harmless.

## Revealing

```http
POST /api/v1/secrets/{id}/reveal
{ "read_token": "<base64url(32 B)>" }
```

```json
{ "kind": "text", "ciphertext": "…", "views_remaining": 0,
  "destroyed": true, "size_bytes": 108 }
```

A wrong token answers 403 with `attempts_left` and consumes no read. Once the
budget is exhausted the secret is destroyed and the answer becomes 410.

## Recipient deletion

```http
DELETE /api/v1/secrets/{id}
X-Peek-Token: <base64url(read token)>
```

`204` on success, `404` when the sender did not allow it. The token may also be
sent in a JSON body as `read_token`; the header keeps it out of any proxy log.

## Sender receipt

```http
GET  /api/v1/secrets/{id}/receipt
POST /api/v1/secrets/{id}/burn
X-Peek-Token: <base64url(receipt token)>
```

```json
{ "id": "…", "status": "active", "kind": "text", "views_used": 0, "views_max": 1,
  "views_remaining": 1, "created_at": "…", "expires_at": "…",
  "last_viewed_at": null, "has_passphrase": true, "url": "…" }
```

`status` is one of `active`, `viewed`, `expired`, `burned`, `deleted`,
`locked`. It keeps answering after the secret is gone, from the tombstone.
`burn` answers `204`.

## Attachments

A file is encrypted in the browser **before** it is uploaded, in chunks, with
the format described in [CRYPTO.md](CRYPTO.md#6-files). The server stores an
opaque stream and its length; the name, the MIME type and the per-file key live
inside the sealed payload of each recipient's secret.

### Uploading

```http
POST /api/v1/files
Content-Type: application/octet-stream
Content-Length: 1048625
X-Peek-CSRF: <the peek_csrf cookie>

<the encrypted stream, header included>
```

`Content-Length` is required: the storage backend writes exactly that many
bytes, and S3 needs the length to sign a non-chunked `PUT`. A body shorter or
longer than announced is refused and nothing is kept.

```json
{ "id": "mKQ7s1eWQmSb9dJ0vV0kHg",
  "token": "<base64url(32 B)>",
  "size": 1048625,
  "expires_at": "2026-11-20T16:43:45Z" }
```

`token` is the **claim token**. It is handed out once and stored hashed: it is
what proves, at creation time, that you are the one who uploaded this blob.
Without it, anyone who guessed an id could attach somebody else's upload to
their own secret.

An uploaded blob that no secret claims before `expires_at`
(`policy.upload_window`, two hours by default) is collected by the purge.

### Attaching

Add `files` to the creation request:

```json
{ "id": "…", "kind": "file", "ciphertext": "…",
  "files": [ { "id": "mKQ7s1eWQmSb9dJ0vV0kHg", "token": "<claim token>" } ] }
```

The blobs become unreachable when every secret that references them is gone and
no download grant is outstanding — so they really disappear on the last read or
when the sender burns the secret, not merely at the original expiry.

### Downloading

A successful reveal of a secret that has attachments returns two extra fields:

```json
{ "kind": "file", "ciphertext": "…", "destroyed": true,
  "download_token": "<base64url(32 B)>",
  "download_expires_at": "2026-11-20T15:13:45Z" }
```

That grant is the only way to fetch the blobs, and it exists because the secret
row is already deleted by the time a one-read secret is revealed: without it, a
100 MiB attachment would become unreadable at the instant it became readable.
It lasts `policy.download_window` (thirty minutes by default).

```http
GET /api/v1/files/{id}
X-Peek-Download: <base64url(grant)>
```

```http
200 OK
Content-Type: application/octet-stream
Content-Length: 1048625
```

The grant travels in a header, never in a query string: proxies log URLs, and a
grant in somebody's access log is a readable secret. A missing grant, an
expired one, or one issued for another bundle all answer `404` — a recipient
must not be able to probe which it was.

## Several recipients

One secret, several links, each with its own key, expiry, reads, passphrase and
audit trail — and **one** upload of the attachments shared between them.

```http
POST /api/v1/secrets
```

```json
{
  "recipients": [
    { "id": "…", "kind": "file", "ciphertext": "…", "read_token_hash": "…",
      "receipt_token_hash": "…", "kdf": { … }, "ttl_seconds": 86400, "views": 1 },
    { "id": "…", "kind": "file", "ciphertext": "…", "read_token_hash": "…",
      "receipt_token_hash": "…", "kdf": { … }, "ttl_seconds": 3600, "views": 3 }
  ],
  "files": [ { "id": "…", "token": "…" } ]
}
```

Each entry is exactly the single-secret body. Sending both forms at once — top
level fields *and* `recipients` — answers `400`: it would be ambiguous which
settings apply. The limit is `policy.max_recipients` (ten by default).

```json
{ "bundle_id": "<the first link's id>",
  "secrets": [ { "id": "…", "url": "…", … }, { "id": "…", "url": "…", … } ] }
```

Creation is all-or-nothing: a half-created bundle would hand a recipient a link
whose attachments were never attached.

## Secret requests

"Send me the password for account X." The direction is inverted: the person
asking must be the only one able to read, and the person answering must not be
able to read back what they deposited.

The requester's browser generates a P-256 key pair. The public half is stored
here so an answer can be sealed to it; the private half never leaves the
fragment of the requester's own tracking link. A symmetric **request key**,
carried in the deposit link, seals the prompt and proves possession — it plays
exactly the role a content key plays for a secret.

The deposit link is `/q/{id}#v1q.<base64url(request key || public key)>`, and
the tracking link is
`/qs/{id}#v1r.<base64url(private || public)>~<request key>~<receipt token>`.
**The public key is in the link, not fetched from this API**, on purpose: a
server that served its own public key instead could read every answer, and a
browser that only ever takes it from the fragment cannot be fooled that way.

### Creating a request

```http
POST /api/v1/requests
```

```json
{ "id": "…", "public_key": "<base64url(65 B, uncompressed SEC1 P-256)>",
  "read_token_hash": "…", "receipt_token_hash": "…",
  "prompt_enc": "<base64url(nonce || AES-256-GCM)>",
  "kdf": { "salt": "…", "memory_kib": 19456, "iterations": 2, "parallelism": 1 },
  "ttl_seconds": 86400, "max_deposits": 1, "notify_email": "me@acme.com" }
```

A `public_key` that is not a point on P-256 is refused with `422`: an invalid
point would be an attack on the depositor's own key exchange.

```json
{ "id": "…", "max_deposits": 1, "expires_at": "…", "created_at": "…",
  "url": "https://secrets.acme.com/q/…" }
```

### Answering one

```http
GET  /api/v1/requests/{id}        → { "id", "deposits_remaining", "expires_at", "kdf" }
POST /api/v1/requests/{id}/open   → { "id", "prompt_enc", "expires_at" }
```

`open` takes `{ "read_token": "…" }`, derived from the request key in the link,
and releases the prompt. It consumes nothing: the prompt is not the answer, and
a depositor may well reload the page before they are ready.

```http
POST /api/v1/requests/{id}/deposit
```

```json
{ "read_token": "…",
  "wrapped_key": "<base64url(125 B: ephemeral public || nonce || sealed content key)>",
  "secret": { "id": "…", "kind": "text", "ciphertext": "…", … },
  "files": [ { "id": "…", "token": "…" } ] }
```

`secret` is an ordinary creation body: a deposit *is* a secret, which is why it
inherits the whole lifecycle — views, expiry, purge, audit — for free. What
makes it a deposit is `wrapped_key`: the content key sealed to the requester's
public key with ECIES (ephemeral ECDH, HKDF-SHA256, AES-256-GCM).

The counter and the secret move together in one transaction, so a single-use
request accepts exactly one answer even with several nodes. Answer `410`
(`closed`) once it is full.

### Following a request

```http
POST /api/v1/requests/{id}/receipt
{ "receipt_token": "…" }
```

```json
{ "id": "…", "max_deposits": 1, "deposits_used": 1, "deposits_remaining": 0,
  "created_at": "…", "expires_at": "…",
  "deposits": [ { "secret_id": "…", "wrapped_key": "…", "kdf": { … },
                  "has_passphrase": false, "size_bytes": 108,
                  "created_at": "…", "views_remaining": 1 } ] }
```

The requester unwraps each `wrapped_key` with the private key from their own
fragment, derives the read token from the content key, and reads the deposit
through the ordinary `POST /api/v1/secrets/{id}/reveal`.

```http
DELETE /api/v1/requests/{id}
{ "receipt_token": "…" }
```

`204`. Closing a request never destroys an answer already received: deposits
keep their own lifecycle, so the door shuts without burning what is inside.

## Audit

```http
GET /api/v1/audit?secret_id=…&event=…&limit=200&offset=0
```

```json
{ "count": 3, "events": [
  { "id": 3, "org_id": "default", "secret_id": "…", "event": "secret.revealed",
    "at": "2026-11-20T14:44:02Z", "ip": "203.0.113.5", "user_agent": "…",
    "detail": { "views_remaining": "0", "destroyed": "true" } } ] }
```

Events: `secret.created`, `secret.page_viewed`, `secret.revealed`,
`secret.bad_passphrase`, `secret.burned`, `secret.deleted`, `secret.expired`,
`secret.purged`, `secret.not_found`, `secret.file_uploaded`,
`secret.file_downloaded`, `request.created`, `request.opened`,
`request.deposited`, `request.closed`, `request.not_found`,
`token.created`, `token.revoked`, `token.scope_refused`,
`request.rate_limited`, `request.admin_blocked`. Secret content never appears,
and a test asserts it.

## Instance

```http
GET /api/v1/instance
```

```json
{ "version": "0.1.0", "crypto_version": "v1", "uptime_seconds": 1204,
  "driver": "sqlite", "active_secrets": 12, "multi_org": false,
  "public_listener": true }
```

## Scripting it

`peek-cli` already does all of this and encrypts locally:

```bash
echo -n "s3cret" | peek-cli push --server https://secrets.acme.com --views 1 --ttl 24h
peek-cli get "https://secrets.acme.com/s/<id>#v1.<key>" --passphrase "…"
```

Writing your own client means implementing format v1 — start from
[CRYPTO.md](CRYPTO.md) and make `crypto/vectors/v1.json` pass.
