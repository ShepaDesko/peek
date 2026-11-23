# Decisions

The specification (section 14) listed ten questions to ask before starting, and
said to apply the default and record it if no answer came. No answers were
given, so every default was applied. They are recorded here with their
consequences, and each can be revisited.

## From section 14 of the specification

| # | Question | Decision | Consequence |
|---|---|---|---|
| 1 | Backend language | **Go** | One static binary, no runtime to install, native systemd deployment |
| 2 | Default database | **SQLite**, PostgreSQL optional | Zero dependency for a single node; PostgreSQL lands with HA in M9 and currently refuses to start |
| 3 | Repository visibility | **Private**, update URL configurable | Customers cannot pull GitHub releases without a token: set `update_url` to a mirror, or use `peek update --file` |
| 4 | Licence | **Proprietary** | See `LICENSE`; redistribution needs written permission |
| 5 | Distributions | **Debian 12/13, Ubuntu 22.04/24.04, Rocky/Alma 9** | `.deb` and `.rpm`, amd64 and arm64, install tested in CI |
| 6 | SSO providers | **Entra ID + generic OIDC**, LDAP later | The `AuthProvider` interface is planned for M5; nothing is implemented yet |
| 7 | Maximum file size | **100 MiB** | `policy.max_file_bytes`; file support itself is M7 |
| 8 | Load balancers to document | **Kemp first, then HAProxy and nginx** | F5, Apache and Traefik are documented too |
| 9 | Anonymous creation | **Disabled by default** | `security.anonymous_create`; an exposed instance is not an open relay out of the box |
| 10 | Languages | **French and English** | French is the default; the visitor's choice is remembered |

## Decisions taken while building

### The client generates the secret identifier

The browser generates the 128-bit identifier and binds it into the AES-GCM
additional data. A ciphertext therefore cannot be moved to another identifier,
and the server rejects a duplicate instead of overwriting. Cost: a (vanishingly
rare) collision has to be retried by the client.

### The read token is a proof of possession, not a password

The server stores `SHA-256(read token)` and compares in constant time before
releasing anything. This is what makes "a preview bot spends no read" and "a
wrong passphrase costs nothing" true at the same time, with one mechanism.

### The receipt token is generated client side

The sender's page is authorised by a random token whose hash alone is stored.
No account is needed to follow or burn a secret, and the server cannot forge a
receipt. Both tokens live in the fragment of the receipt URL.

### A tombstone outlives the secret

Deleting a secret writes a small row holding its status and counters — never
content — so the sender's receipt page can still say "read" or "expired" after
the data is gone.

### HKDF is implemented by hand in the browser

WebCrypto only exposes extract-then-expand, while the Go reference uses expand
alone for sub-keys. The browser implements both halves over HMAC-SHA256 so the
two sides are byte-identical, which the shared vectors check.

### `wasm-unsafe-eval` is in the CSP

Argon2id runs as WebAssembly, and `script-src 'self'` alone blocks WebAssembly
compilation — found by running the real page in a real browser, not in review.
`'wasm-unsafe-eval'` permits WebAssembly only; it allows neither `eval()` nor
inline script, and `'unsafe-inline'` and `'unsafe-eval'` remain absent. A test
asserts all three facts.

### Fallback colours sit in a CSS layer

The binary serves `/branding.css` unlayered, and the bundled stylesheet keeps
its defaults in `@layer base`. Unlayered rules win over any layer, so an
instance brand overrides the defaults without `!important` and without a
rebuild.

### Unfinished areas refuse loudly

`database.driver = "postgres"` and `tls.mode = "acme"` return an explicit error
naming the milestone instead of silently falling back. A silent fallback to
SQLite across several nodes would break the single-read guarantee; a silent
fallback from ACME would serve plain HTTP on a listener an operator believes is
encrypted.

### 404 rather than 403 on a network gate

A caller from a disallowed network, or one probing an admin route on the public
listener, gets the same answer as for a route that does not exist.

### Handlers live in `internal/server`

The specification sketched `internal/api` next to `internal/server`. Splitting
HTTP handlers from the router they are mounted on would have added a package
boundary and a shared helper package without separating anything meaningful.
Business rules are in `internal/secrets`, data access in `internal/store`, and
`internal/server` owns the HTTP surface.

### Playwright drives the built binary

The end-to-end suite starts the real binary with its embedded interface rather
than a dev server, so what CI exercises is what ships.

### P-256 for secret requests, not X25519

The specification allowed either. X25519 only reached Safari and Firefox
recently, and Peek is deployed in managed enterprise browsers that are
routinely several versions behind the release channel; P-256 ECDH has been in
every WebCrypto implementation for a decade. A key exchange that works
everywhere beats a slightly nicer curve that fails for a tenth of the users
with an error they cannot act on.

A consequence worth knowing: WebCrypto cannot import a P-256 private key from
the raw scalar alone — a JWK needs `x` and `y`, and support for a PKCS#8 key
without its public half varies between browsers. So the tracking link carries
both halves. It costs 65 bytes in a URL and removes a whole class of
browser-specific failure.

### No AWS SDK for the S3 backend

Peek signs SigV4 itself and speaks the five S3 operations it needs. Two
reasons, neither of them about the SDK's quality. It would add roughly ten
megabytes to a binary with a sixty-megabyte budget. And its default credential
chain probes the instance-metadata endpoint, which is an outbound call Peek
promises not to make: credentials come from `peek.toml` and nowhere else.

The signing code is about two hundred lines, and the test suite verifies it
against an independent transcription of the specification, then against a real
MinIO before each release.

### A download grant, rather than keeping the secret alive

The row of a one-read secret is deleted inside the transaction that consumes
the last read. Without something else, a 100 MiB attachment would become
unreachable at the instant it became readable. A successful reveal therefore
hands out a short-lived grant, stored hashed like every other token, and the
blobs' expiry is pushed past the end of it. Keeping the secret row alive "just
for the files" would have been the other option, and it would have meant a
secret that is readable after it was supposed to be gone.

### Webhook endpoints live in the configuration file, not in the API

Every other product in this space lets a user add a webhook URL in the
interface. Peek does not, and will not.

An endpoint URL that a caller can set turns the server into a request
forwarder: it will connect to anything reachable from where it runs, which on
an on-premise installation is the customer's own network — the metadata
service, the management interface of the hypervisor, an unauthenticated
internal API. The usual mitigation is a blocklist of private ranges, and Peek
is *installed in* those private ranges, so the blocklist would have to forbid
exactly the hosts a legitimate webhook points at.

So the vector is removed instead of filtered. Endpoints are `[[webhook]]`
tables in `peek.toml`, which only root can write, and the API offers visibility
and retries over that list and nothing else. The cost is real: adding an
endpoint needs a configuration change and a restart. On a product whose whole
claim is that it is safe to install inside a network, that is the right side of
the trade.

### A webhook body is an audit entry, and the field list is a test

The payload could have been built per event, carrying whatever that event had
to hand. Instead every delivery is the same ten fields, taken from the audit
entry that triggered it.

The audit trail is already built never to contain a secret, a key, a
passphrase or a URL fragment — that is rule one of the project, enforced
everywhere it is written. Reusing it means forwarding is safe *by
construction* rather than by review: there is no path where a future event
hands the dispatcher a field nobody thought about. A test asserts the exact
field set, so adding one is a decision somebody has to make on purpose.

### The delivery queue is a database table

The obvious implementation is a goroutine with a channel and a retry loop. It
fails twice. A restart during a retry window drops the event — and the events
worth a webhook are the ones an operator is watching for. And a cluster of
three nodes behind a load balancer sends three copies of everything, because
each one saw the reveal.

Rows in `webhook_deliveries` fix both. The drain is claimed with the same job
lock as the purge, so one node at a time sends, which makes delivery
at-least-once per cluster rather than once per node. The identifier in
`X-Peek-Delivery` is how a receiver makes its own side idempotent; the
documentation says so rather than claiming exactly-once, which no HTTP
notification can honestly offer.

Enqueueing is one small insert on the request path, next to the audit insert
that is already there. Nothing in a handler waits on an outbound call: a
receiver that hangs for thirty seconds cannot slow a reveal by a millisecond.
