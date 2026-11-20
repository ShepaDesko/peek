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
