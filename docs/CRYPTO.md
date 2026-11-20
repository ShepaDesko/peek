# Cryptography — format v1

This document is the normative description of what Peek encrypts, where each
key lives, and what the server is able to learn. Two implementations follow it
— Go (`internal/crypto`, used by the server and `peek-cli`) and TypeScript
(`web/src/crypto`, used by the browser) — and they are pinned together by
shared test vectors that both must reproduce byte for byte.

## 1. Primitives

| Purpose | Primitive |
|---|---|
| Payload encryption | AES-256-GCM, 96-bit nonce, 128-bit tag |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| Passphrase stretching | Argon2id, 19 456 KiB, 2 passes, 1 lane, 32-byte output |
| Read-token digest | SHA-256 |
| Randomness | `crypto/rand` (Go), `crypto.getRandomValues` (browser) |

Argon2id runs as WebAssembly in the browser. Those parameters follow current
OWASP guidance and stay usable on a mid-range phone (roughly 100–300 ms); they
are stored per secret, so they can be raised later without breaking old links.

## 2. Values and where they live

| Value | Size | Where it exists |
|---|---|---|
| Content key `K` | 32 B | Generated in the browser; lives **only** in the URL fragment |
| Passphrase | — | Only in the sender's and recipient's heads; never transmitted |
| KDF salt | 16 B | Stored server side (public, useless alone) |
| Final key | 32 B | Derived in the browser, never transmitted |
| Encryption key | 32 B | Derived in the browser, never transmitted |
| Read token | 32 B | Derived in the browser, sent **once** to prove possession |
| `SHA-256(read token)` | 32 B | Stored server side |
| Receipt token | 32 B | Generated in the browser, kept in the receipt URL fragment |
| `SHA-256(receipt token)` | 32 B | Stored server side |
| Ciphertext | n | Stored server side |

A URL fragment (`#…`) is never sent in an HTTP request. Combined with
`Referrer-Policy: no-referrer` and a CSP that forbids third-party origins, the
key cannot leak to the server, to a proxy, or to another site.

## 3. Derivation

```
A      = passphrase = ""  ?  (nothing)  :  Argon2id(passphrase, salt, m, t, p, 32)
final  = HKDF-SHA256(ikm = K ‖ A, salt = salt, info = "peek-key-v1",  len = 32)
enc    = HKDF-Expand(final, info = "peek-enc-v1",  len = 32)
token  = HKDF-Expand(final, info = "peek-read-v1", len = 32)
stored = SHA-256(token)
```

`HKDF-Expand` is the expand half alone, without a second extract. WebCrypto
only exposes the combined form, so the browser implements extract and expand
over HMAC-SHA256 directly — that is why `web/src/crypto/hkdf.ts` exists, and
why the vectors cover it.

## 4. Sealing

```
AAD   = "peek-v1|" ‖ secret_id
blob  = nonce(12 random bytes) ‖ AES-256-GCM(enc, nonce, plaintext, AAD)
```

The public identifier is generated **by the client** (16 random bytes,
base64url) and bound into the AAD, so a ciphertext cannot be moved from one
identifier to another. The server rejects a duplicate identifier rather than
overwriting.

The plaintext is a JSON payload; the kind, the sender's message and any file
name are inside the ciphertext, never in metadata:

```json
{ "v": 1, "kind": "text", "text": "…", "message": "…" }
```

## 5. Proof of possession before reveal

This is the step that makes the click-to-reveal guarantee real.

1. `GET /api/v1/secrets/{id}` returns public metadata only: whether a
   passphrase is needed, the KDF parameters, the reads left, the expiry. **No
   read is consumed**, which is why a link-preview bot (Teams, Slack, Outlook
   Safe Links, a mail antivirus) costs nothing.
2. The browser derives the read token and sends it to
   `POST /api/v1/secrets/{id}/reveal`.
3. The server compares `SHA-256(token)` with the stored digest **in constant
   time**. On mismatch it increments a failure counter and returns 403 with the
   attempts left; no read is spent and no ciphertext is released. After
   `security.max_passphrase_attempts` failures the secret is destroyed.
4. On match, within a single transaction, the server decrements the read
   counter with a conditional `UPDATE … WHERE views_remaining > 0`, checks that
   exactly one row changed — which is the proof this caller won the race — and
   deletes the row when the last read is spent.

Fifty simultaneous reads of a one-read secret therefore produce exactly one
success. That property is tested at the store level and over HTTP
(`internal/store/store_test.go`, `internal/server/server_test.go`).

## 6. Link formats

```
recipient:  https://host/s/<id>#v1.<base64url(K)>
sender:     https://host/r/<id>#v1.<base64url(K)>~<base64url(receipt token)>
```

The sender's page holds both tokens: the content key, to rebuild the recipient
link, and the receipt token, which authorises status checks and burning. Both
stay in the fragment.

## 7. What the server can and cannot do

**Cannot**: read a secret, recover a passphrase, brute-force a key (256-bit,
uniformly random), prove which secret a given ciphertext belongs to without its
identifier, or restore a secret once it is consumed.

**Can**, and this is deliberate: know that a secret exists, its size, when it
was created, when it expires, how many reads remain, whether it carries a
passphrase, and the IP addresses that interacted with it (subject to
`security.anonymize_ips`).

**A compromised server** can serve modified JavaScript to future visitors and
capture what they type. Zero-knowledge protects data at rest and in transit, not
a backend you no longer control. [THREAT-MODEL.md](THREAT-MODEL.md) says what
to do about it.

## 8. Test vectors

`crypto/vectors/v1.json` holds four cases: without a passphrase, with a
passphrase at the default parameters, with a passphrase at cheap parameters,
and an empty plaintext. Each case fixes the inputs **and the expected
outputs** — final key, encryption key, read token, its digest, the sealed blob
for a fixed nonce, and the fragment.

```bash
go test ./internal/crypto/...      # Go reads the vectors
npm run test --prefix web          # TypeScript reads the same file
go run ./tools/genvectors          # regenerate; CI fails if the file changes
```

CI regenerates the vectors and fails on any diff: changing the format without
bumping its version is caught before it ships.

## 9. Changing the format

Version `v1` is frozen. A new format gets `v2`, a new set of `info` strings and
its own vectors; `v1` stays readable so existing links keep working. The
version prefixes every fragment, so a client always knows what it is holding.
