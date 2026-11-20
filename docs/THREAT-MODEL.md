# Threat model

This document says what Peek protects against, what it does not, and which
decisions follow from that. It is meant to be read before a deployment, and
quoted honestly to a customer who asks "so you can't read our secrets?".

## Assets

1. The content of a secret — the thing everything else exists for.
2. The passphrase, when one is used.
3. Metadata: who shared what, with whom, when, from which address.
4. The instance itself: availability, configuration, master key.

## What an attacker can be

| Attacker | Capability |
|---|---|
| A passer-by with the link | Has the URL, therefore the key. Treated as the recipient. |
| A network observer | Sees TLS traffic. Sees no fragment: it is never sent. |
| A link-preview bot | Fetches the page automatically (Teams, Slack, Outlook Safe Links, mail antivirus). |
| A curious administrator of the host | Full access to the database, the files and the logs. |
| A thief of a backup | Has the archive, including ciphertexts and the master key. |
| An attacker on the network | Can reach the exposed listener and guess identifiers. |
| An attacker who compromises the server | Can change the code Peek serves. |

## What is protected

**A stolen database tells an attacker nothing about content.** Every payload is
AES-256-GCM with a key that never reaches the server. There is no key escrow,
no recovery mechanism and no administrator override — on purpose.

**A link-preview bot never destroys a secret.** Fetching the page returns
metadata only. Spending a read requires a POST carrying a token derived from
the key, which a bot does not have. This is the click-to-reveal step, on by
default and forceable by policy.

**Guessing a passphrase costs the attacker, not the recipient.** A wrong
passphrase produces a wrong read token, which is rejected before any read is
spent. After `security.max_passphrase_attempts` failures the secret is
destroyed. Guessing a 256-bit identifier is not practical, and guessing the key
even less so.

**A read is spent exactly once.** The decrement is a conditional `UPDATE` in a
transaction, checked by row count; fifty concurrent readers of a one-read
secret produce exactly one success. Tested at both the store and the HTTP
layer.

**A consumed secret is gone.** The row is deleted inside the same transaction,
not flagged. A per-minute job purges whatever expired. Only a tombstone (status
and counters) and the audit trail remain, and neither holds content.

**The admin surface can be made unreachable from the internet.** Two listeners
plus CIDR gates, and `peek doctor --external` verifies the result rather than
trusting the configuration.

**A forged client IP does not work.** Forwarded headers are honoured only from
declared proxies; everywhere else the peer address wins. Rate limits, gates and
audit entries are therefore written against an address an attacker cannot
choose.

**Nothing leaves the host by default.** No CDN, no font service, no analytics,
no telemetry. Outbound traffic happens only for SMTP, an IdP, webhooks and the
update check — each of which you configure, and each of which can be off. Peek
runs air-gapped.

## What is not protected

**A compromised server can serve modified JavaScript.** This is the structural
limit of browser-side encryption, and no amount of design removes it: whoever
controls the code the browser runs can capture what the browser sees. What Peek
does about it: a strict CSP with no third-party origin and no inline script;
hashed, immutable assets served from the binary; a hardened systemd unit with a
read-only filesystem; and signed releases so the binary itself cannot be
swapped unnoticed. What you should do about it: treat the host as a
high-value system, keep it patched, watch the audit trail, and prefer a
passphrase for genuinely sensitive material — it is never sent and therefore
cannot be captured server-side without a *targeted* code change.

**Whoever has the link has the secret.** The key is in the URL. A link shared
in a group chat is a secret shared with that group. A passphrase on a second
channel is the answer, which is why Peek never sends the passphrase by e-mail,
even when it is sending the link.

**The recipient's device is out of scope.** A revealed secret can be screenshot,
copied, logged by a password manager or synced somewhere. Peek controls its own
page: `no-store`, no browser cache, nothing written to local storage except a
language and a theme preference.

**Metadata is visible to the server, and that is the trade.** Existence,
size, timings, reads and IP addresses are what make the audit trail, the
expiry and the rate limiting work. `security.anonymize_ips` keeps only a /24 or
/48 prefix; `security.audit_retention` bounds how long any of it is kept.

**A backup is as sensitive as the live database, plus the master key.** See
[BACKUP.md](BACKUP.md): encrypt the archive, keep the retention short.

**Denial of service is bounded, not eliminated.** Rate limits per real client
IP, body size caps and timeouts raise the cost; sizing the pipe and the load
balancer in front is still your job.

**Plain HTTP breaks the product, not just its transport.** WebCrypto is only
available in a secure context, so an instance served over `http://` on anything
other than localhost cannot encrypt at all. The interface says so instead of
failing obscurely, and `peek doctor` warns about an `http://` public URL.

**An old browser may be unable to decrypt.** WebCrypto, WebAssembly and
`'wasm-unsafe-eval'` support are required. The page says so rather than failing
silently.

## Decisions that follow

| Decision | Reason |
|---|---|
| The key lives in the fragment, never in a query string | Query strings land in proxy and server logs |
| `Referrer-Policy: no-referrer` everywhere | Stops the fragment-bearing URL leaking to another site |
| Proof of possession before releasing a ciphertext | Lets a wrong passphrase, and a bot, cost nothing |
| Identical answer for expired, consumed and unknown | A caller cannot enumerate what exists |
| 404, not 403, from a CIDR gate | An unauthorised network learns nothing |
| Creation disabled by default | An exposed instance is not an open relay on day one |
| The release signature is verified by the updater, with the key in the binary | The update path does not depend on trusting a web server |
| PostgreSQL and ACME refuse rather than approximate | A silent fallback would break the single-read guarantee, or serve plain HTTP |

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
