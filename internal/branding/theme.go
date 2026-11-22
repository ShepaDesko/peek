package branding

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// The resolved brand of an instance: what peek.toml says, with whatever an
// administrator saved in the database layered on top.
//
// Every stored field may be empty, and empty means "keep the default". That is
// what lets an administrator change one colour without having to restate the
// whole brand.

// Font is one of the typefaces an administrator may pick.
//
// These are font *stacks* of faces the operating system already has, not font
// files. The brief asked for a list embedded in the binary; a stack goes
// further in the same direction, since the browser downloads nothing at all —
// which is the point of the rule, and keeps the binary small.
type Font struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Stack string `json:"stack"`
}

// Fonts is the list offered in the customisation page.
var Fonts = []Font{
	{
		ID:    "system",
		Label: "Système",
		Stack: `ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif`,
	},
	{
		ID:    "grotesque",
		Label: "Grotesque",
		Stack: `"Inter", "Helvetica Neue", Helvetica, Arial, ui-sans-serif, system-ui, sans-serif`,
	},
	{
		ID:    "humanist",
		Label: "Humaniste",
		Stack: `"Optima", "Segoe UI", Candara, "Gill Sans", ui-sans-serif, system-ui, sans-serif`,
	},
	{
		ID:    "serif",
		Label: "Serif",
		Stack: `ui-serif, Georgia, Cambria, "Times New Roman", Times, serif`,
	},
	{
		ID:    "mono",
		Label: "Monospace",
		Stack: `ui-monospace, "SFMono-Regular", "Cascadia Mono", Menlo, Consolas, monospace`,
	},
}

// FontStack returns the CSS stack for an identifier, or the default.
func FontStack(id string) string {
	for _, f := range Fonts {
		if f.ID == id {
			return f.Stack
		}
	}
	return Fonts[0].Stack
}

// Radius is a corner rounding preset.
type Radius struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// Radii are the corner presets. Free-form CSS lengths are deliberately not
// accepted: a brand setting should not be able to produce an unusable layout.
var Radii = []Radius{
	{ID: "square", Label: "Carré", Value: "4px"},
	{ID: "soft", Label: "Adouci", Value: "10px"},
	{ID: "round", Label: "Arrondi", Value: "16px"},
	{ID: "pill", Label: "Pilule", Value: "999px"},
}

// RadiusValue returns the CSS length for a preset.
func RadiusValue(id string) string {
	for _, r := range Radii {
		if r.ID == id {
			return r.Value
		}
	}
	return Radii[1].Value
}

// ButtonStyle is how the primary button is drawn.
type ButtonStyle struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// ButtonStyles are the presets.
var ButtonStyles = []ButtonStyle{
	{ID: "solid", Label: "Plein"},
	{ID: "outline", Label: "Contour"},
}

// ButtonStyleID normalises a stored value.
func ButtonStyleID(id string) string {
	for _, s := range ButtonStyles {
		if s.ID == id {
			return s.ID
		}
	}
	return ButtonStyles[0].ID
}

// TextKeys are the strings an administrator may override, per language.
//
// They are listed here rather than being free-form so that the customisation
// page can show a labelled field for each, and so that a typo in a key cannot
// silently produce a text nobody ever sees.
var TextKeys = []string{
	"home.title",
	"home.subtitle",
	"home.help",
	"recipient.message",
	"recipient.expired",
	"footer.text",
	"email.signature",
}

// Texts is language → key → value.
type Texts map[string]map[string]string

// ParseTexts reads the stored JSON, keeping only known keys and languages.
func ParseTexts(raw string, languages []string) Texts {
	out := Texts{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	var decoded map[string]map[string]string
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return out
	}
	allowedKey := map[string]bool{}
	for _, k := range TextKeys {
		allowedKey[k] = true
	}
	for lang, entries := range decoded {
		if !contains(languages, lang) {
			continue
		}
		for key, value := range entries {
			if !allowedKey[key] || strings.TrimSpace(value) == "" {
				continue
			}
			if out[lang] == nil {
				out[lang] = map[string]string{}
			}
			out[lang][key] = clampText(value)
		}
	}
	return out
}

// MarshalTexts renders texts for storage, dropping anything unknown.
func MarshalTexts(texts Texts, languages []string) (string, error) {
	cleaned := Texts{}
	allowedKey := map[string]bool{}
	for _, k := range TextKeys {
		allowedKey[k] = true
	}
	for lang, entries := range texts {
		if !contains(languages, lang) {
			continue
		}
		for key, value := range entries {
			if !allowedKey[key] || strings.TrimSpace(value) == "" {
				continue
			}
			if cleaned[lang] == nil {
				cleaned[lang] = map[string]string{}
			}
			cleaned[lang][key] = clampText(value)
		}
	}
	buf, err := json.Marshal(cleaned)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// clampText bounds one stored string. A brand text is a sentence, not a page.
func clampText(v string) string {
	v = strings.TrimSpace(v)
	const maxRunes = 500
	runes := []rune(v)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return v
}

// Resolved is the brand the interface receives.
type Resolved struct {
	ServiceName   string            `json:"service_name"`
	PrimaryColor  string            `json:"primary_color"`
	AccentColor   string            `json:"accent_color"`
	Background    string            `json:"background_color,omitempty"`
	Font          string            `json:"font"`
	FontStack     string            `json:"font_stack"`
	Radius        string            `json:"corner_radius"`
	RadiusValue   string            `json:"corner_radius_value"`
	ButtonStyle   string            `json:"button_style"`
	HidePoweredBy bool              `json:"hide_powered_by"`
	SupportURL    string            `json:"support_url"`
	LegalURL      string            `json:"legal_url"`
	PrivacyURL    string            `json:"privacy_url"`
	ContactEmail  string            `json:"contact_email,omitempty"`
	Language      string            `json:"language"`
	Palette       map[string]string `json:"palette"`
	Texts         Texts             `json:"texts,omitempty"`
	// Assets maps a kind to the URL that serves it, already cache-busted.
	Assets map[string]string `json:"assets,omitempty"`
	// CustomCSS is served through /branding.css, never inlined.
	HasCustomCSS bool     `json:"has_custom_css"`
	Warnings     []string `json:"warnings,omitempty"`
	// Version changes whenever anything above does, and drives the ETag.
	Version int `json:"version"`
}

// Resolve layers the stored brand over the configured defaults.
func Resolve(cfg *config.Config, stored *store.Branding, assets []store.BrandingAsset, languages []string) Resolved {
	base := FromConfig(cfg)

	r := Resolved{
		ServiceName:   base.ServiceName,
		PrimaryColor:  base.PrimaryColor,
		AccentColor:   base.AccentColor,
		Font:          Fonts[0].ID,
		Radius:        Radii[1].ID,
		ButtonStyle:   ButtonStyles[0].ID,
		HidePoweredBy: base.HidePoweredBy,
		SupportURL:    base.SupportURL,
		LegalURL:      base.LegalURL,
		PrivacyURL:    base.PrivacyURL,
		Language:      base.Language,
	}

	if stored != nil {
		r.ServiceName = orDefault(stored.ServiceName, r.ServiceName)
		r.PrimaryColor = orDefault(stored.PrimaryColor, r.PrimaryColor)
		r.AccentColor = orDefault(stored.AccentColor, r.AccentColor)
		r.Background = strings.TrimSpace(stored.BackgroundColor)
		r.Font = orDefault(stored.Font, r.Font)
		r.Radius = orDefault(stored.CornerRadius, r.Radius)
		r.ButtonStyle = ButtonStyleID(orDefault(stored.ButtonStyle, r.ButtonStyle))
		r.HidePoweredBy = stored.HidePoweredBy
		r.SupportURL = orDefault(stored.SupportURL, r.SupportURL)
		r.LegalURL = orDefault(stored.LegalURL, r.LegalURL)
		r.PrivacyURL = orDefault(stored.PrivacyURL, r.PrivacyURL)
		r.ContactEmail = stored.ContactEmail
		r.Texts = ParseTexts(stored.Texts, languages)
		r.HasCustomCSS = strings.TrimSpace(stored.CustomCSS) != ""
		r.Version = stored.Version
	}

	r.FontStack = FontStack(r.Font)
	r.RadiusValue = RadiusValue(r.Radius)
	r.Palette, r.Warnings = BuildPalette(r.PrimaryColor, r.AccentColor)
	if r.Background != "" {
		if _, err := parseHex(r.Background); err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("background colour %q is not a valid hex colour and was ignored", r.Background))
			r.Background = ""
		}
	}

	if len(assets) > 0 {
		r.Assets = map[string]string{}
		for _, a := range assets {
			r.Assets[a.Kind] = fmt.Sprintf("/branding/%s?v=%s", a.Kind, a.ETag)
		}
	}
	return r
}

// CSS renders the stylesheet the interface loads before anything else.
func (r Resolved) CSS(customCSS string) string {
	var b strings.Builder
	b.WriteString("/* Generated by Peek from the instance branding. Do not edit. */\n:root {\n")
	for _, key := range sortedKeys(r.Palette) {
		fmt.Fprintf(&b, "  --peek-%s: %s;\n", key, r.Palette[key])
	}
	fmt.Fprintf(&b, "  --peek-radius: %s;\n", r.RadiusValue)
	fmt.Fprintf(&b, "  --peek-font: %s;\n", r.FontStack)
	if r.Background != "" {
		fmt.Fprintf(&b, "  --peek-bg: %s;\n", r.Background)
	}
	b.WriteString("}\n")

	// The brand decides the shape of the primary button, within two presets.
	if r.ButtonStyle == "outline" {
		b.WriteString(`
.peek-btn-primary {
  background: transparent;
  color: var(--peek-primary);
  border-color: var(--peek-primary);
}

.peek-btn-primary:hover:not(:disabled) {
  background: var(--peek-primary-soft);
}
`)
	}

	if clean := SanitizeCSS(customCSS); clean != "" {
		b.WriteString("\n/* Custom CSS, from the instance administrator. */\n")
		b.WriteString(clean)
		b.WriteString("\n")
	}
	return b.String()
}

// ETag fingerprints the resolved brand, including its assets and version.
func (r Resolved) ETag() string {
	h := sha256.New()
	fields := []string{
		r.ServiceName, r.PrimaryColor, r.AccentColor, r.Background, r.Font, r.Radius,
		r.ButtonStyle, r.SupportURL, r.LegalURL, r.PrivacyURL, r.ContactEmail, r.Language,
		fmt.Sprint(r.HidePoweredBy), fmt.Sprint(r.HasCustomCSS), fmt.Sprint(r.Version),
	}
	for _, kind := range sortedKeys(r.Assets) {
		fields = append(fields, kind, r.Assets[kind])
	}
	for _, lang := range sortedTextLanguages(r.Texts) {
		for _, key := range sortedKeys(r.Texts[lang]) {
			fields = append(fields, lang, key, r.Texts[lang][key])
		}
	}
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return `"` + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:12]) + `"`
}

func sortedTextLanguages(t Texts) []string {
	out := make([]string, 0, len(t))
	for lang := range t {
		out = append(out, lang)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
