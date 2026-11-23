# White-labelling

Peek is meant to be installed at a customer and look like **their** service,
not like a product they bought.

There are two ways in. `peek.toml` holds the fallback identity, used on a
fresh install and before anything has been saved. Everything else lives in the
database, per organisation, and is edited in **Administration →
Personnalisation** with a live preview of the home page, the recipient page
and an e-mail. The database wins where both are set.

## What `peek.toml` holds

```toml
[branding]
service_name   = "Coffre ACME"
primary_color  = "#1d4ed8"
accent_color   = "#0e9488"
hide_powered_by = true
support_url    = "https://support.acme.example"
legal_url      = "https://acme.example/mentions-legales"
privacy_url    = "https://acme.example/confidentialite"

default_language = "fr"
```

```bash
sudo peek config check && sudo systemctl restart peek
```

The name appears in the header, the tab title and the footer. The two colours
generate a full palette, which the interface consumes as CSS custom properties.

## The generated palette

From `primary_color` and `accent_color`, Peek derives:

```
--peek-primary          --peek-accent
--peek-primary-hover    --peek-accent-soft
--peek-primary-active   --peek-on-primary
--peek-primary-soft
--peek-primary-ring
```

`--peek-on-primary` is chosen by measuring the **WCAG 2.2 contrast ratio** of
white and near-black against your primary, and picking the better one. If
neither reaches 4.5:1, the theme carries a warning rather than quietly
rendering unreadable text:

```bash
curl -s https://secrets.acme.com/api/v1/branding | jq .warnings
```

```json
["contrast between the primary colour and white text is 3.12:1, below the 4.5:1 required by WCAG 2.2 AA; pick a darker primary"]
```

Accessibility is a stated requirement of the product, so a brand that fails it
is reported, not hidden.

## How it reaches the browser

```http
GET /api/v1/branding   → the theme as JSON (ETag, revalidated)
GET /branding.css      → the same theme as CSS custom properties
```

`index.html` loads `/branding.css` before the bundle. The bundled stylesheet
keeps its own defaults inside `@layer base`, and CSS cascade layers rank
unlayered rules above every layer — so the instance brand always wins, with no
`!important` and no rebuild. Change a colour, restart, reload: it is applied.

Dark mode follows the system preference and can be toggled by the visitor; the
choice is remembered in that browser only.

## Moving a brand between instances

```bash
peek branding export acme.peekbrand     # or to stdout
peek branding import acme.peekbrand
```

The file is JSON: format version, export date, and the theme. Prepare a brand
once on a staging instance and deploy it at the customer, or keep it in the
customer's configuration repository. Import validates the result and prints any
contrast warning before you restart.

## Domain

Single-tenant, which is the default: `public_url` is the brand's domain. All
links, cookies and redirects derive from it.

[Multi-organisation mode](CONFIG.md#multi-organisation-mode) resolves the
brand from the `Host` header, taken only from a trusted proxy or a direct
connection, and only for a domain a DNS TXT record has proved. Each
organisation has its own brand, and an e-mail sent on behalf of one carries
that one.

## What the editor adds

- A live preview of the home page, the recipient page and an e-mail, updating
  as you type.
- Light and dark logos (SVG sanitised server side, PNG, WebP), a favicon and
  an Open Graph image.
- Corner radius, button style, and a font chosen from a list **embedded in the
  binary** — never a web font fetched from the internet, because that is a
  third party watching every recipient open a secret.
- Every text editable per enabled language: titles, help, the default
  recipient message, the expired-secret page, the footer.
- Custom CSS, administrator only, sanitised, size-limited, with no `@import`
  and no external `url()`.
- Branded e-mail templates, HTML and text, with variables, a preview and a
  "send a test" button.

## Moving a brand between instances

```bash
# prepare it once
sudo peek branding export > acme.peekbrand

# and at the customer
sudo peek branding import acme.peekbrand
```

The file carries the colours, the texts and the assets. It does not carry
users, secrets or keys.

## The contrast check

The palette is generated from one primary colour, and the text drawn on it is
whichever of white or near-black actually reaches 4.5:1 — WCAG 2.2 AA for
normal text. When neither does, the editor says so instead of quietly shipping
a button nobody can read.

That check is the reason a brand cannot make the interface inaccessible by
accident, and it is also why `--peek-on-primary` exists as a variable rather
than being hard-coded to white.
