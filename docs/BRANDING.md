# White-labelling

Peek is meant to be installed at a customer and look like **their** service,
not like a product they bought. Today that is driven by `peek.toml`, served to
the browser as JSON and as a stylesheet. The administration page with a live
preview, logo upload, custom texts per language and branded e-mail templates is
milestone M6; the pieces below are the foundation it will edit.

## What you can change today

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

Multi-organisation (milestone M9) resolves the brand from the `Host` header,
taken only from a trusted proxy or a direct connection, with domains verified
by a DNS TXT record.

## Arriving in milestone M6

- Administration page with a live preview of the home page, the recipient page
  and an e-mail.
- Light and dark logos (SVG sanitised server side, PNG, WebP), favicon
  generation, Open Graph image.
- Corner radius, button style and a font chosen from a list **embedded in the
  binary** — never a web font fetched from the internet.
- Every text editable per enabled language: titles, help, default recipient
  message, the expired-secret page, the footer.
- Custom CSS, administrator only, sanitised, size-limited, with no `@import`
  and no external `url()`.
- Branded e-mail templates (HTML and text) with variables, a preview and a
  "send a test" button.

Everything above is already in the data model and in `peek.toml`; M6 adds the
editor, storage in the database, and the assets.
