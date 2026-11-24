// Package branding resolves the white-label theme: name, colours, texts and
// the generated CSS variables the interface uses.
//
// The palette is generated from two colours so that an operator only picks a
// primary and an accent, and the contrast ratio of the generated text colours
// is checked against WCAG 2.2 AA rather than assumed.
package branding

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/ShepaDesko/peek/internal/config"
)

// Theme is the resolved brand for one organisation.
type Theme struct {
	ServiceName   string            `json:"service_name"`
	PrimaryColor  string            `json:"primary_color"`
	AccentColor   string            `json:"accent_color"`
	HidePoweredBy bool              `json:"hide_powered_by"`
	SupportURL    string            `json:"support_url"`
	LegalURL      string            `json:"legal_url"`
	PrivacyURL    string            `json:"privacy_url"`
	Language      string            `json:"language"`
	DefaultTheme  string            `json:"default_theme"`
	Palette       map[string]string `json:"palette"`
	// Warnings lists contrast problems an administrator should fix. They are
	// surfaced, not silently corrected.
	Warnings []string `json:"warnings,omitempty"`
}

// FromConfig builds the theme from peek.toml. Stored branding layers on top.
func FromConfig(cfg *config.Config) Theme {
	b := cfg.Branding
	t := Theme{
		ServiceName:   orDefault(b.ServiceName, "Peek"),
		PrimaryColor:  orDefault(b.PrimaryColor, "#4f46e5"),
		AccentColor:   orDefault(b.AccentColor, "#0ea5e9"),
		HidePoweredBy: b.HidePoweredBy,
		SupportURL:    b.SupportURL,
		LegalURL:      b.LegalURL,
		PrivacyURL:    b.PrivacyURL,
		Language:      orDefault(cfg.DefaultLanguage, "fr"),
		DefaultTheme:  orDefault(b.DefaultTheme, "dark"),
	}
	t.Palette, t.Warnings = BuildPalette(t.PrimaryColor, t.AccentColor, cfg.Branding.Colors)
	return t
}

// PaletteKeys are the tokens a brand may override, in the order an editor
// should show them. A key outside this list is refused rather than ignored:
// a typo in a colour name must not silently leave the derived value in place.
var PaletteKeys = []string{
	"primary", "primary-hover", "primary-active", "primary-soft", "primary-ring",
	"on-primary", "accent", "accent-soft",
}

// ValidPaletteKey reports whether a token may be overridden.
func ValidPaletteKey(key string) bool {
	for _, k := range PaletteKeys {
		if k == key {
			return true
		}
	}
	return false
}

// BuildPalette generates the full set of CSS variables from two colours and
// reports any AA contrast failure it had to work around.
//
// `overrides` replaces derived tokens, token name to hex colour. It is a
// request, not a licence: the contrast of the final pair is measured after the
// overrides are applied, so pinning an unreadable on-primary still warns.
func BuildPalette(primary, accent string, overrides map[string]string) (map[string]string, []string) {
	var warnings []string
	p, err := parseHex(primary)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("primary colour %q is not a valid hex colour, falling back to #4f46e5", primary))
		p, _ = parseHex("#4f46e5")
	}
	a, err := parseHex(accent)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("accent colour %q is not a valid hex colour, falling back to #0ea5e9", accent))
		a, _ = parseHex("#0ea5e9")
	}

	palette := map[string]string{
		"primary":        p.hex(),
		"primary-hover":  p.mix(rgb{0, 0, 0}, 0.12).hex(),
		"primary-active": p.mix(rgb{0, 0, 0}, 0.24).hex(),
		"primary-soft":   p.mix(rgb{255, 255, 255}, 0.88).hex(),
		"primary-ring":   p.mix(rgb{255, 255, 255}, 0.55).hex(),
		"accent":         a.hex(),
		"accent-soft":    a.mix(rgb{255, 255, 255}, 0.88).hex(),
	}

	// Text on the primary surface: whichever of white or near-black reads
	// better against it. The contrast is not judged here but after the
	// overrides below, so a pinned colour is measured on the same terms.
	white, _ := parseHex("#ffffff")
	ink, _ := parseHex("#0b1020")
	darkText := contrast(p, ink) > contrast(p, white)
	if darkText {
		palette["on-primary"] = ink.hex()
	} else {
		palette["on-primary"] = white.hex()
	}

	warnings = append(warnings, applyOverrides(palette, overrides)...)

	// Whatever the palette ended up as, derived or pinned, the text on the
	// primary surface has to be readable. Measuring after the overrides is
	// what keeps an override a request rather than a way around AA.
	finalPrimary, errPrimary := parseHex(palette["primary"])
	finalOn, errOn := parseHex(palette["on-primary"])
	if errPrimary == nil && errOn == nil {
		if ratio := contrast(finalPrimary, finalOn); ratio < 4.5 {
			advice := "pick a darker primary"
			if darkText {
				advice = "pick a lighter primary"
			}
			if _, pinned := overrides["on-primary"]; pinned {
				advice = "pick another text colour, or let Peek choose it"
			}
			warnings = append(warnings, fmt.Sprintf(
				"contrast between the primary colour and the text on it is %.2f:1, below the 4.5:1 required by WCAG 2.2 AA; %s", ratio, advice))
		}
	}
	return palette, warnings
}

// applyOverrides layers pinned colours over the derived palette.
//
// An unknown token or an unusable value is reported and skipped, never
// silently dropped: a brand that asked for a colour and did not get it must
// find out from the warnings rather than from a screenshot.
func applyOverrides(palette map[string]string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return nil
	}
	var warnings []string
	for _, key := range sortedKeys(overrides) {
		value := strings.TrimSpace(overrides[key])
		if value == "" {
			continue
		}
		if !ValidPaletteKey(key) {
			warnings = append(warnings, fmt.Sprintf(
				"%q is not a palette token and was ignored; the tokens are %s", key, strings.Join(PaletteKeys, ", ")))
			continue
		}
		c, err := parseHex(value)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"colour %q for %s is not a valid hex colour and was ignored", value, key))
			continue
		}
		palette[key] = c.hex()
	}
	return warnings
}

// CSS renders the theme as a stylesheet of custom properties. Serving it as a
// file rather than an inline style block is what lets the CSP keep
// style-src 'self' with no unsafe-inline.
func (t Theme) CSS() string {
	var b strings.Builder
	b.WriteString("/* Generated by Peek from the instance branding. Do not edit. */\n:root {\n")
	for _, key := range sortedKeys(t.Palette) {
		fmt.Fprintf(&b, "  --peek-%s: %s;\n", key, t.Palette[key])
	}
	b.WriteString("}\n")
	return b.String()
}

// ETag returns a short, stable fingerprint of the theme for caching.
func (t Theme) ETag() string {
	var h uint64 = 1469598103934665603
	for _, s := range []string{t.ServiceName, t.PrimaryColor, t.AccentColor, t.Language,
		strconv.FormatBool(t.HidePoweredBy), t.SupportURL, t.LegalURL, t.PrivacyURL} {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= 1099511628211
		}
	}
	return fmt.Sprintf("\"%x\"", h)
}

type rgb struct{ r, g, b float64 }

func parseHex(s string) (rgb, error) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return rgb{}, fmt.Errorf("expected #rrggbb")
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return rgb{}, err
	}
	return rgb{
		r: float64((v >> 16) & 0xff),
		g: float64((v >> 8) & 0xff),
		b: float64(v & 0xff),
	}, nil
}

func (c rgb) hex() string {
	clamp := func(v float64) int {
		switch {
		case v < 0:
			return 0
		case v > 255:
			return 255
		default:
			return int(math.Round(v))
		}
	}
	return fmt.Sprintf("#%02x%02x%02x", clamp(c.r), clamp(c.g), clamp(c.b))
}

// mix blends towards other by t (0 keeps c, 1 returns other).
func (c rgb) mix(other rgb, t float64) rgb {
	return rgb{
		r: c.r + (other.r-c.r)*t,
		g: c.g + (other.g-c.g)*t,
		b: c.b + (other.b-c.b)*t,
	}
}

// luminance is the WCAG relative luminance.
func (c rgb) luminance() float64 {
	channel := func(v float64) float64 {
		v /= 255
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(c.r) + 0.7152*channel(c.g) + 0.0722*channel(c.b)
}

// contrast returns the WCAG contrast ratio between two colours.
func contrast(a, b rgb) float64 {
	la, lb := a.luminance(), b.luminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Contrast is the exported form, used by tests and the branding preview.
func Contrast(a, b string) (float64, error) {
	ca, err := parseHex(a)
	if err != nil {
		return 0, err
	}
	cb, err := parseHex(b)
	if err != nil {
		return 0, err
	}
	return contrast(ca, cb), nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
