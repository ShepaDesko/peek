# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: an IT department sending a password to a client.** A technician has
just created an account, a VPN profile or an admin password and has to get it to
someone outside their organisation — by e-mail, Teams or over the phone — in the
next two minutes. They are at a desk, in a hurry, and they do this several times
a day.

**The recipient never chose Peek.** They receive a link from someone they trust,
open it on whatever is to hand (often a phone, often a managed corporate browser
several versions behind), and must understand in seconds what this is, that it
is safe, and that it will disappear. They have no account and will never have
one. They may not know what "zero-knowledge" means.

Confirmed secondary contexts, all of them real: a white-label deployment at each
client of a service provider, each instance wearing that client's brand; an
internal IT department sharing credentials between colleagues; both at once on
one installation.

**Administrators** configure the instance, set policy, read the audit trail and
run `peek doctor` from a shell. They see a different, denser surface.

## Product Purpose

Peek replaces the password pasted into an e-mail, a chat thread or a ticket —
where it stays readable for years, to everyone with access to that mailbox or
that archive. A secret goes in, a link comes out, the link works a fixed number
of times and then the secret is gone from the server.

Success is a technician who stops thinking about it: sending a credential
through Peek has to be as fast as pasting it, or they will paste it.

## Positioning

**The server cannot read what it stores, and that is provable rather than
promised.** The content key is generated in the recipient's browser and lives
only in the URL fragment, which is never sent in an HTTP request. The server
holds ciphertext, a salt and the SHA-256 of a read token. A competitor running
the same features on a server that holds the key cannot truthfully say this.

Three consequences a neighbouring product cannot copy-paste:

- **A link preview costs nothing.** Reading metadata consumes no read, so Teams,
  Slack, Outlook Safe Links and mail antivirus scanners do not burn the secret
  before the human arrives. Every competitor with a one-click reveal has this
  problem.
- **One read means one read, under concurrency.** The guarantee is a conditional
  `UPDATE` and its row count, so forty simultaneous readers through a load
  balancer across two nodes produce exactly one winner. Measured, not asserted.
- **It is installed, not subscribed.** A native Linux binary under systemd, no
  Docker, no outbound call by default, wearing the customer's own brand. It runs
  inside a network that does not reach the internet.

## Operating Context

The sender's scene is a corporate desktop, a ticket open in another tab, under
time pressure. The link is then pasted into an e-mail or a chat window, and the
passphrase — when there is one — goes by a second channel, usually a phone call
or an SMS.

The recipient's scene is the opposite: a link arriving out of context, often on
a phone, often from a sender they half expected. The question they are actually
asking is "is this real, and what happens if I click".

The administrator's scene is a terminal and a configuration file. `peek doctor`
is the surface they trust.

## Capabilities and Constraints

- Secret kinds: text or password, URL, file attachments up to 100 MiB, several
  recipients per secret with one upload shared between them, and secret
  *requests* (asking someone to send you something, sealed to a key only you
  hold).
- Per-secret controls: expiry (5 minutes to 30 days), number of reads (1 to
  100), optional passphrase, a click-to-reveal step, recipient deletion.
- The sender gets a receipt page that keeps answering — read, expired, burned —
  after the secret itself is gone.
- Accounts, roles (`member`, `manager`, `auditor`, `admin`, `platform_admin`),
  OIDC single sign-on, scoped API tokens, signed webhooks, an audit trail that
  never contains content.
- **WebCrypto needs a secure context.** Over plain HTTP on anything but
  localhost the interface loads, says so, and refuses to encrypt. This state is
  real and must be designed, not hidden.
- Argon2id runs in the browser as WebAssembly: roughly 100–300 ms on a
  mid-range phone, with no spinner budget to waste.
- French is the default language; English is the other. Every string goes
  through `web/src/lib/i18n.ts` in both.

## Brand Commitments

Four constraints the user confirmed as untouchable:

1. **White-label is the product.** Primary and accent colours, the service name,
   the logo, the fonts and the footer links come from `peek.toml` and from the
   database, per organisation. An instance is "Coffre NORDEX", not "Peek". The
   design must therefore be a *system that survives an arbitrary primary
   colour*, not a palette: identity has to live in structure, typography,
   composition and motion, because the colour belongs to the customer.
   `--peek-on-primary` is chosen by measuring WCAG contrast and warns rather
   than silently rendering unreadable text.
2. **Nothing external at runtime.** No CDN, no web font fetched from the
   internet, no analytics, no third-party script. Everything ships inside the
   binary; Peek must run air-gapped.
3. **The current copy stays.** The redesign changes form, not words.
4. **The page budget holds.** Recipient JavaScript under 150 kB gzipped
   (Argon2id WebAssembly included; measured at 131.3 kB), CSS under 40 kB,
   binary under 60 MB. `make budget` fails the build otherwise. No heavy
   animation library.

The one failure mode the user named: **generic**. A screenshot that could be any
SaaS is the only outcome they would reject.

**Standing visual preference, set by the user (23 November 2026).** The
direction is the category standard played straight, at the craft level of
**NordVPN / NordPass**: a vault that reads as simple, clean and confident rather
than clever. Not a stylistic exercise — the trust comes from how finished it
looks, not from how unusual it is. Two things follow and both are binding:

- **White-label is the headline feature, not a theme option.** Logo, colours,
  service name and typography belong to the customer, and the interface has to
  look deliberately art-directed in anyone's colour. The customisation surface
  deserves to be good, not an afterthought in a settings tab.
- **The default instance keeps today's look.** Out of the box it stays close to
  what ships now — the same dark/light pair, the same layout vocabulary — and
  the work is raising its finish, not replacing its world. This is a refinement,
  not a redesign; the concept round was run and the user chose convention
  deliberately.

Deferred by the user on the same day: mockups and the redesign itself are for a
later session.

## Evidence on Hand

- A working product at v1.0.2, validated on a Debian 13 virtual machine: 372
  creations and 372 reads per second on one vCPU, 5–7 MB resident at rest, a 100
  MiB attachment through real TLS at 106 MB/s.
- Real measured numbers in `docs/PERFORMANCE.md`; the threat model in
  `docs/THREAT-MODEL.md`; the format specification in `docs/CRYPTO.md`.
- The existing interface in `web/src`, in French and English, with a working
  white-label theme pipeline (`/branding.css`, CSS cascade layers), a dark/light
  toggle and an axe-core accessibility suite over WCAG 2.2 AA.
- No customers, logos, testimonials, pricing or case studies exist. None may be
  invented.

## Product Principles

1. **The recipient is the one who did not sign up.** Their page is the product's
   face, and it has to earn trust from a stranger in one viewport on a phone.
2. **Say what is true, show it where possible.** "The server never sees the key"
   is the whole claim; it deserves to be demonstrated, not printed in grey 12px.
3. **Fast beats featureful.** A technician who finds Peek slower than pasting
   will paste.
4. **Security before convenience, visibly.** Where the product refuses
   something, it refuses loudly and explains. Those refusals are part of the
   interface, not errors to hide.
5. **The customer's brand wins over ours.** Everything distinctive must survive
   someone else's colour.

## Accessibility & Inclusion

WCAG 2.2 level AA is a shipped requirement, enforced by an axe-core suite across
18 end-to-end tests: a skip link, live-region errors, a full keyboard path,
visible focus, and contrast checked against the customer's chosen colours with a
warning when they fail. The interface must stay usable in a managed corporate
browser several versions behind the release channel.
