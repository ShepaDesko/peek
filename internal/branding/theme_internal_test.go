package branding

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The generated stylesheet has to be able to paint the light surface before
// the bundle loads, so the same declarations exist twice: here, and in
// web/src/styles.css under html[data-theme="light"]. Two copies of a palette
// drift, and the way it shows up is a themed instance flashing the wrong
// colours for one frame — the kind of thing nobody files a bug about.
func TestLightSurfaceMatchesStylesheet(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "styles.css"))
	if err != nil {
		t.Skipf("stylesheet not readable: %v", err)
	}
	css := string(raw)

	const marker = `html[data-theme="light"] {`
	start := strings.Index(css, marker)
	if start < 0 {
		t.Fatalf("styles.css no longer declares %s", marker)
	}
	rest := css[start+len(marker):]
	end := strings.Index(rest, "}")
	if end < 0 {
		t.Fatal("the light theme block is not closed")
	}

	fromCSS := declarations(rest[:end])
	fromGo := declarations(lightSurface)

	if len(fromCSS) == 0 {
		t.Fatal("no declarations read from the stylesheet")
	}
	if len(fromCSS) != len(fromGo) {
		t.Fatalf("stylesheet has %d declarations, lightSurface has %d:\n css: %v\n  go: %v",
			len(fromCSS), len(fromGo), fromCSS, fromGo)
	}
	for i := range fromCSS {
		if fromCSS[i] != fromGo[i] {
			t.Errorf("declaration %d: stylesheet %q, lightSurface %q", i, fromCSS[i], fromGo[i])
		}
	}
}

// declarations reduces a CSS block to its sorted "property: value" pairs, so
// the comparison is about content rather than whitespace or ordering.
func declarations(block string) []string {
	var out []string
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if line == "" || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			continue
		}
		property, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out = append(out, strings.TrimSpace(property)+": "+strings.TrimSpace(value))
	}
	sort.Strings(out)
	return out
}

func TestDefaultThemeCSS(t *testing.T) {
	// Dark is what the bundle already says, so nothing is generated for it:
	// an empty rule would only be one more thing to keep in step.
	if got := defaultThemeCSS("dark"); got != "" {
		t.Errorf("dark generated %q", got)
	}
	if got := defaultThemeCSS(""); got != "" {
		t.Errorf("an unset default generated %q", got)
	}

	light := defaultThemeCSS("light")
	if !strings.Contains(light, ":root:not([data-theme])") {
		t.Errorf("the light default must not beat a visitor's own choice: %q", light)
	}
	if !strings.Contains(light, "--peek-bg: #f6f7fb") || !strings.Contains(light, "--peek-scheme: light") {
		t.Errorf("the light default does not carry the surface: %q", light)
	}

	system := defaultThemeCSS("system")
	if !strings.Contains(system, "@media (prefers-color-scheme: light)") {
		t.Errorf("the system default does not consult the system: %q", system)
	}
	if !strings.Contains(system, ":root:not([data-theme])") {
		t.Errorf("the system default must not beat a visitor's own choice: %q", system)
	}
	// Nesting must not break the declarations.
	if !strings.Contains(system, "--peek-text: #15182a") {
		t.Errorf("the nested block lost a declaration: %q", system)
	}
	if strings.Count(system, "{") != strings.Count(system, "}") {
		t.Errorf("unbalanced braces: %q", system)
	}
}

// A tinted background must be derived from the surface that is actually
// painted. --peek-primary-soft cannot do it: BuildPalette computes it at 88 %
// white whatever the theme, because it exists for the light one. Used as a
// background it is a pale plate, and on the dark theme the text over it is
// pale too — around 1.3:1, and only while the pointer rests there, which is
// why neither a screenshot nor an axe run that does not hover ever saw it.
//
// Rule 6 of docs/DESIGN.md. This test is what keeps it from coming back.
func TestNoPaleTokenUsedAsABackground(t *testing.T) {
	offender := regexp.MustCompile(`background(-color)?:[^;}]*--peek-(primary|accent)-soft`)

	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "styles.css"))
	if err != nil {
		t.Skipf("stylesheet not readable: %v", err)
	}
	for _, hit := range offender.FindAllString(string(raw), -1) {
		t.Errorf("web/src/styles.css: %q — derive it from var(--peek-surface) instead", hit)
	}

	// Both button presets, since the outline one writes its own rules.
	for _, style := range []string{"solid", "outline"} {
		css := Resolved{ButtonStyle: style, Palette: map[string]string{"primary": "#4f46e5"}}.CSS("")
		for _, hit := range offender.FindAllString(css, -1) {
			t.Errorf("generated stylesheet (%s buttons): %q", style, hit)
		}
	}
}
