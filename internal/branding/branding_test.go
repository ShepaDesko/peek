package branding_test

import (
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/branding"
	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

func TestPaletteAndContrast(t *testing.T) {
	// A dark primary passes with white text.
	palette, warnings := branding.BuildPalette("#1d4ed8", "#0e9488")
	if palette["primary"] != "#1d4ed8" {
		t.Fatalf("primary = %q", palette["primary"])
	}
	if palette["on-primary"] != "#ffffff" {
		t.Fatalf("on-primary = %q, want white on a dark primary", palette["on-primary"])
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	// A pale primary gets dark text instead of silently unreadable white.
	palette, _ = branding.BuildPalette("#fef08a", "#0ea5e9")
	if palette["on-primary"] == "#ffffff" {
		t.Fatal("white text was chosen on a pale primary")
	}

	// A mid-tone that passes neither way is reported rather than hidden.
	_, warnings = branding.BuildPalette("#797979", "#0ea5e9")
	if len(warnings) == 0 {
		t.Fatal("a primary that fails AA both ways produced no warning")
	}
	if !strings.Contains(strings.Join(warnings, " "), "WCAG") {
		t.Fatalf("the warning does not mention the standard: %v", warnings)
	}

	// Nonsense falls back and says so.
	_, warnings = branding.BuildPalette("not-a-colour", "#0ea5e9")
	if len(warnings) == 0 {
		t.Fatal("an invalid colour produced no warning")
	}
}

func TestCustomCSSRefusesWhatReachesOutside(t *testing.T) {
	ok := []string{
		"",
		".peek-card { border-width: 2px }",
		":root { --peek-primary: #123456 }\n.peek-btn { letter-spacing: .02em }",
	}
	for _, css := range ok {
		if _, err := branding.CheckCSS(css); err != nil {
			t.Errorf("CheckCSS(%q) refused valid CSS: %v", css, err)
		}
	}

	refused := map[string]string{
		"import":          `@import url("https://evil.example/x.css");`,
		"remote image":    `.peek-card { background: url(https://evil.example/pixel.png) }`,
		"data image":      `.peek-card { background: url(data:image/png;base64,AAAA) }`,
		"expression":      `.peek-card { width: expression(alert(1)) }`,
		"behaviour":       `.peek-card { behavior: url(#default#time2) }`,
		"escaped import":  `@\69 mport "https://evil.example/x.css";`,
		"commented out":   "/* nothing */ .x { background: ur\\l(https://evil.example/p.png) }",
		"style break out": `.x {} </style><script>alert(1)</script>`,
	}
	for name, css := range refused {
		if _, err := branding.CheckCSS(css); err == nil {
			t.Errorf("%s was accepted: %s", name, css)
		}
	}

	// Too large is refused by size, not by content.
	if _, err := branding.CheckCSS(strings.Repeat("a", branding.MaxCustomCSSBytes+1)); err == nil {
		t.Error("oversized CSS was accepted")
	}

	// On the serving path a refusal becomes silence, never a partial rule.
	if out := branding.SanitizeCSS(`@import "x";`); out != "" {
		t.Errorf("SanitizeCSS let a refused stylesheet through: %q", out)
	}
}

func TestImageDetectionAndSVGRefusal(t *testing.T) {
	png := append([]byte{0x89}, []byte("PNG\r\n\x1a\n")...)
	if ct, err := branding.DetectImage(png); err != nil || ct != branding.TypePNG {
		t.Fatalf("PNG detected as %q (%v)", ct, err)
	}

	webp := append([]byte("RIFF\x00\x00\x00\x00"), []byte("WEBP")...)
	if ct, err := branding.DetectImage(webp); err != nil || ct != branding.TypeWebP {
		t.Fatalf("WebP detected as %q (%v)", ct, err)
	}

	if _, err := branding.DetectImage([]byte("MZ\x90\x00 this is an executable")); err == nil {
		t.Fatal("an executable was accepted as an image")
	}

	plain := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>`)
	if ct, err := branding.ValidateAsset("logo_light", plain); err != nil || ct != branding.TypeSVG {
		t.Fatalf("a plain SVG was refused: %q %v", ct, err)
	}

	dangerous := map[string][]byte{
		"script":       []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"handler":      []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`),
		"remote image": []byte(`<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.example/p.png"/></svg>`),
		"entity":       []byte(`<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "b">]><svg xmlns="http://www.w3.org/2000/svg"></svg>`),
		"foreign":      []byte(`<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body/></foreignObject></svg>`),
	}
	for name, data := range dangerous {
		if _, err := branding.ValidateAsset("logo_light", data); err == nil {
			t.Errorf("an SVG with %s was accepted", name)
		}
	}

	oversized := make([]byte, branding.MaxAssetBytes+1)
	copy(oversized, png)
	if _, err := branding.ValidateAsset("logo_light", oversized); err == nil {
		t.Error("an oversized image was accepted")
	}
}

func TestResolveLayersStoredOverConfigured(t *testing.T) {
	cfg := config.Default()
	cfg.Branding.ServiceName = "Peek"
	cfg.Branding.PrimaryColor = "#4f46e5"
	cfg.DefaultLanguage = "fr"

	// With nothing stored, the configuration is the brand.
	bare := branding.Resolve(&cfg, nil, nil, []string{"fr", "en"})
	if bare.ServiceName != "Peek" || bare.PrimaryColor != "#4f46e5" {
		t.Fatalf("unexpected default brand: %+v", bare)
	}
	if bare.FontStack == "" || bare.RadiusValue == "" {
		t.Fatal("the resolved brand has no font or radius")
	}

	// A stored brand overrides field by field; empty means "keep the default".
	stored := store.Branding{
		ServiceName:  "Coffre ACME",
		PrimaryColor: "#1d4ed8",
		Font:         "serif",
		CornerRadius: "pill",
		ButtonStyle:  "outline",
		Texts:        `{"fr":{"home.title":"Partagez en confiance","unknown.key":"x"},"de":{"home.title":"x"}}`,
		CustomCSS:    ".peek-card { border-width: 2px }",
		Version:      7,
	}
	assets := []store.BrandingAsset{{Kind: store.AssetLogoLight, ETag: "abc123"}}

	r := branding.Resolve(&cfg, &stored, assets, []string{"fr", "en"})
	if r.ServiceName != "Coffre ACME" || r.PrimaryColor != "#1d4ed8" {
		t.Fatalf("stored values did not win: %+v", r)
	}
	if r.AccentColor != cfg.Branding.AccentColor {
		t.Fatalf("an unset field did not fall back: %q", r.AccentColor)
	}
	if !strings.Contains(r.FontStack, "serif") || r.RadiusValue != "999px" {
		t.Fatalf("font or radius not applied: %q %q", r.FontStack, r.RadiusValue)
	}
	if r.Texts["fr"]["home.title"] != "Partagez en confiance" {
		t.Fatalf("texts not resolved: %+v", r.Texts)
	}
	if _, ok := r.Texts["fr"]["unknown.key"]; ok {
		t.Fatal("an unknown text key was kept")
	}
	if _, ok := r.Texts["de"]; ok {
		t.Fatal("a text in a language the instance does not offer was kept")
	}
	if r.Assets[store.AssetLogoLight] != "/branding/logo_light?v=abc123" {
		t.Fatalf("asset URL = %q", r.Assets[store.AssetLogoLight])
	}
	if !r.HasCustomCSS || r.Version != 7 {
		t.Fatalf("unexpected flags: %+v", r)
	}
}

func TestCSSOutputAndETag(t *testing.T) {
	cfg := config.Default()
	stored := store.Branding{PrimaryColor: "#1d4ed8", ButtonStyle: "outline", Version: 1}
	r := branding.Resolve(&cfg, &stored, nil, []string{"fr"})

	css := r.CSS(".peek-card { border-width: 2px }")
	for _, want := range []string{"--peek-primary: #1d4ed8", "--peek-radius:", "--peek-font:", ".peek-btn-primary", "border-width: 2px"} {
		if !strings.Contains(css, want) {
			t.Errorf("the stylesheet is missing %q:\n%s", want, css)
		}
	}
	// Refused CSS never reaches the stylesheet.
	if strings.Contains(r.CSS(`@import "https://evil.example/x.css";`), "evil.example") {
		t.Fatal("refused custom CSS was served")
	}

	// The ETag follows every visible change.
	first := r.ETag()
	stored.PrimaryColor = "#b91c1c"
	changed := branding.Resolve(&cfg, &stored, nil, []string{"fr"}).ETag()
	if first == changed {
		t.Fatal("the ETag did not change with the brand")
	}
	same := branding.Resolve(&cfg, &store.Branding{PrimaryColor: "#1d4ed8", ButtonStyle: "outline", Version: 1}, nil, []string{"fr"}).ETag()
	if same != first {
		t.Fatal("the ETag is not stable for an unchanged brand")
	}
}

func TestTextsRoundTrip(t *testing.T) {
	texts := branding.Texts{
		"fr": {"home.title": "Bonjour", "nope": "ignored"},
		"en": {"home.title": "Hello"},
		"de": {"home.title": "Hallo"},
	}
	raw, err := branding.MarshalTexts(texts, []string{"fr", "en"})
	if err != nil {
		t.Fatal(err)
	}
	back := branding.ParseTexts(raw, []string{"fr", "en"})
	if back["fr"]["home.title"] != "Bonjour" || back["en"]["home.title"] != "Hello" {
		t.Fatalf("round trip lost a text: %+v", back)
	}
	if _, ok := back["de"]; ok {
		t.Fatal("an unsupported language survived")
	}
	if _, ok := back["fr"]["nope"]; ok {
		t.Fatal("an unknown key survived")
	}

	// A text that is far too long is clamped rather than refused: the
	// administrator sees a shortened string instead of a lost form.
	long := branding.Texts{"fr": {"home.title": strings.Repeat("é", 900)}}
	raw, err = branding.MarshalTexts(long, []string{"fr"})
	if err != nil {
		t.Fatal(err)
	}
	if runes := []rune(branding.ParseTexts(raw, []string{"fr"})["fr"]["home.title"]); len(runes) != 500 {
		t.Fatalf("clamped to %d runes, want 500", len(runes))
	}
}
