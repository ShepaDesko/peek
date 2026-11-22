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

## 6. Files

A file never reaches the server in the clear, and it is never held whole in a
tab either: it is sealed chunk by chunk as it is read, and streamed out.

```
stream = header || chunk[0] || chunk[1] || … || chunk[n-1]
header = "PEEKF1" || chunk size (uint32 BE) || nonce prefix (7 B)   = 17 bytes
```

The per-file key `F` is a fresh random 256 bits, carried **inside the sealed
payload** of each recipient's secret — which is why one upload can serve ten
links while the server learns nothing.

```
file enc key = HKDF-Expand(F, "peek-file-v1", 32)
nonce[i]     = nonce prefix || i (uint32 BE) || final flag (0x00 or 0x01)
chunk[i]     = AES-256-GCM(file enc key, nonce[i], plaintext[i], AAD = header)
```

This is the STREAM construction (Rogaway & Hoang), the same shape `age` uses,
and every part of it earns its place:

- the **counter inside the nonce** authenticates order: swap two chunks and
  neither opens, because each was sealed under the counter of its own position;
- the **final flag** authenticates the end of the stream: a truncated file is
  missing the chunk that carries it, so the reader refuses the whole thing
  instead of handing back something shorter. Appending chunks fails the same
  way;
- the **header as AAD** binds the chunk size and the nonce prefix, so neither
  can be rewritten in transit.

Every chunk but the last is exactly `chunk size` bytes of plaintext (1 MiB by
default). An empty file still produces one chunk, final and empty, so the
stream of a zero-byte file is 33 bytes and not a special case anywhere.

The encrypted length is therefore exact and known before the first byte is
read — `17 + plaintext + 16 per chunk` — which is what lets the server check an
announced upload size and sign a non-chunked S3 `PUT`.

Names and MIME types are **not** in the stream. They are in the payload:

```json
{ "v": 1, "kind": "file", "message": "…",
  "files": [ { "id": "…", "name": "vpn.ovpn", "mime": "application/x-openvpn-profile",
               "size": 4096, "key": "<base64url(F)>", "chunk_size": 1048576 } ] }
```

## 7. Secret requests

A secret request inverts the usual direction: the person asking must be the
only one who can read, and the person answering must not be able to read back
what they deposited — nor must anyone who merely holds the request link.

The requester generates a **P-256 key pair**. The public half is stored on the
server so a deposit can be sealed to it; the private half never leaves the
fragment of the requester's own tracking link. A separate symmetric **request
key** `R` travels in the deposit link and plays exactly the role a content key
plays for a secret: `HKDF` gives an encryption key that seals the prompt and a
read token whose digest the server stores.

A deposit is an ordinary v1 secret. What makes it a deposit is that its content
key `K` is wrapped to the requester's public key with ECIES:

```
Z   = ECDH(ephemeral private, requester public)        // 32-byte X coordinate
key = HKDF-SHA256(ikm = Z || ephemeral public || requester public,
                  salt = nil, info = "peek-request-v1")
box = ephemeral public (65 B) || nonce (12 B) || AES-256-GCM(key, nonce, K,
                                                 AAD = "peek-req-v1|" || request id)
```

Both public keys are in the IKM, so the derivation is bound to the exact pair
involved: substituting another ephemeral key lands on different key material
and the box no longer opens. The AAD binds the box to one request, so a deposit
captured from one cannot be replayed into another.

**P-256 and not X25519.** X25519 only reached Safari and Firefox recently, and
Peek runs in managed enterprise browsers that are routinely several versions
behind; P-256 ECDH has been in every WebCrypto implementation for a decade.
The trade is recorded in [DECISIONS.md](DECISIONS.md).

**The public key travels in the link, never through the API.** This is the
load-bearing part. A compromised server that could hand out its own public key
would read every answer; a browser that only ever takes it from the fragment
cannot be fooled that way. Nothing in the deposit page asks the server for a
key.

Invalid points are refused on the way in, both when a request is created and
when a link is parsed: feeding a point that is not on the curve into someone
else's ECDH is a known attack, and it costs one check to close.

## 8. Link formats

```
recipient:  https://host/s/<id>#v1.<base64url(K)>
sender:     https://host/r/<id>#v1.<base64url(K)>~<base64url(receipt token)>
deposit:    https://host/q/<id>#v1q.<base64url(R || requester public key)>
tracking:   https://host/qs/<id>#v1r.<base64url(private || public)>~<R>~<receipt token>
```

The sender's page holds both tokens: the content key, to rebuild the recipient
link, and the receipt token, which authorises status checks and burning. Both
stay in the fragment.

Each prefix is distinct — `v1`, `v1q`, `v1r` — so the three kinds can never be
mistaken for one another: one is a symmetric key, one carries a public key, one
carries a private key. Parsing the wrong kind fails rather than half-works, and
a test asserts it on both sides.

The tracking link carries the private key of the request, which means losing it
means losing the answers. The page says so in as many words; the server has no
copy, by construction.

## 9. What the server can and cannot do

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

## 10. Test vectors

`crypto/vectors/v1.json` holds three families of cases, all with fixed inputs
**and fixed expected outputs**:

- **secrets** — without a passphrase, with a passphrase at the default
  parameters, with a passphrase at cheap parameters, and an empty plaintext.
  Each fixes the final key, the encryption key, the read token, its digest, the
  sealed blob for a fixed nonce, and the fragment.
- **files** — an empty file, a short one, one that is exactly one chunk (no
  spurious trailing chunk), and one of several chunks plus a remainder. Each
  fixes the derived key and the whole stream for a fixed nonce prefix. These
  are the boundaries that get got wrong.
- **secret requests** — a wrapped content key for a fixed key pair, ephemeral
  key and nonce. The box is not reproducible from the TypeScript side without
  the ephemeral private key, so the browser test opens what Go sealed instead:
  one format, two implementations.

```bash
go test ./internal/crypto/...      # Go reads the vectors
npm run test --prefix web          # TypeScript reads the same file
go run ./tools/genvectors          # regenerate; CI fails if the file changes
```

CI regenerates the vectors and fails on any diff: changing the format without
bumping its version is caught before it ships.

## 11. Changing the format

Version `v1` is frozen. A new format gets `v2`, a new set of `info` strings and
its own vectors; `v1` stays readable so existing links keep working. The
version prefixes every fragment, so a client always knows what it is holding.
