package branding

import (
	"os"
	"path/filepath"
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
