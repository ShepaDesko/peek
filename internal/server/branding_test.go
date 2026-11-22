package server_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/config"
)

// A one-pixel PNG, used as an uploaded logo.
var pngPixel = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
	0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
	0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

func TestBrandingIsServedFromTheDatabase(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Branding.ServiceName = "Peek"
		c.Branding.PrimaryColor = "#4f46e5"
	})
	admin := h.signIn(t)

	// Before anything is saved, the configuration is the brand.
	before := decodeBody(t, do(t, h.public, http.MethodGet, "/api/v1/branding", nil, nil))
	if before["service_name"] != "Peek" {
		t.Fatalf("unexpected default brand: %v", before)
	}

	rec := admin.do(t, h.internal, http.MethodPut, "/api/v1/branding/admin", jsonBody(t, map[string]any{
		"service_name":  "Coffre ACME",
		"primary_color": "#1d4ed8",
		"corner_radius": "pill",
		"font":          "serif",
		"button_style":  "outline",
		"support_url":   "https://support.acme.example",
		"texts":         map[string]map[string]string{"fr": {"home.title": "Partagez en confiance"}},
		"custom_css":    ".peek-card { border-width: 2px }",
	}), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("save branding: %d %s", rec.Code, rec.Body.String())
	}

	// Every visitor sees it, including on the public listener.
	after := decodeBody(t, do(t, h.public, http.MethodGet, "/api/v1/branding", nil, nil))
	if after["service_name"] != "Coffre ACME" || after["primary_color"] != "#1d4ed8" {
		t.Fatalf("the saved brand is not served: %v", after)
	}
	if after["corner_radius_value"] != "999px" {
		t.Fatalf("corner radius not applied: %v", after["corner_radius_value"])
	}
	texts, _ := after["texts"].(map[string]any)
	fr, _ := texts["fr"].(map[string]any)
	if fr["home.title"] != "Partagez en confiance" {
		t.Fatalf("texts not served: %v", texts)
	}

	// And so does the stylesheet, with the custom CSS appended.
	css := do(t, h.public, http.MethodGet, "/branding.css", nil, nil)
	if css.Code != http.StatusOK {
		t.Fatalf("branding.css: %d", css.Code)
	}
	body := css.Body.String()
	for _, want := range []string{"--peek-primary: #1d4ed8", "--peek-radius: 999px", "border-width: 2px", ".peek-btn-primary"} {
		if !strings.Contains(body, want) {
			t.Errorf("the stylesheet is missing %q:\n%s", want, body)
		}
	}

	// The ETag follows the brand, so a cached copy is revalidated.
	etag := css.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the stylesheet")
	}
	again := do(t, h.public, http.MethodGet, "/branding.css", nil, map[string]string{"If-None-Match": etag})
	if again.Code != http.StatusNotModified {
		t.Fatalf("a conditional request returned %d, want 304", again.Code)
	}

	// Resetting hands the brand back to peek.toml.
	if rec := admin.do(t, h.internal, http.MethodDelete, "/api/v1/branding/admin", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	restored := decodeBody(t, do(t, h.public, http.MethodGet, "/api/v1/branding", nil, nil))
	if restored["service_name"] != "Peek" {
		t.Fatalf("reset did not restore the configured brand: %v", restored)
	}
}

func TestBrandingRefusesDangerousInput(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	cases := map[string]map[string]any{
		"css that imports":    {"custom_css": `@import url("https://evil.example/x.css");`},
		"css that fetches":    {"custom_css": `.x { background: url(https://evil.example/p.png) }`},
		"javascript link":     {"support_url": "javascript:alert(1)"},
		"link without scheme": {"legal_url": "evil.example/legal"},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := admin.do(t, h.internal, http.MethodPut, "/api/v1/branding/admin", jsonBody(t, body), nil)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422: %s", rec.Code, rec.Body.String())
			}
		})
	}

	// Nothing was stored, so the stylesheet is still clean.
	css := do(t, h.public, http.MethodGet, "/branding.css", nil, nil).Body.String()
	if strings.Contains(css, "evil.example") {
		t.Fatalf("a refused stylesheet reached the browser:\n%s", css)
	}
}

func TestBrandingAssets(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodPut, "/api/v1/branding/assets/logo_light", pngPixel,
		map[string]string{"Content-Type": "image/png"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	uploaded := decodeBody(t, rec)
	url, _ := uploaded["url"].(string)
	if !strings.HasPrefix(url, "/branding/logo_light?v=") {
		t.Fatalf("unexpected asset URL: %v", uploaded)
	}

	// The recipient page needs the logo, so it is served on both listeners.
	served := do(t, h.public, http.MethodGet, url, nil, nil)
	if served.Code != http.StatusOK {
		t.Fatalf("serve asset: %d", served.Code)
	}
	if ct := served.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content type %q", ct)
	}
	if !bytes.Equal(served.Body.Bytes(), pngPixel) {
		t.Fatal("the served bytes differ from the uploaded ones")
	}
	if cc := served.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("a digest-stamped URL is not immutable: %q", cc)
	}
	if csp := served.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Fatalf("an asset is served without a sandbox: %q", csp)
	}

	// The theme now advertises it.
	theme := decodeBody(t, do(t, h.public, http.MethodGet, "/api/v1/branding", nil, nil))
	assets, _ := theme["assets"].(map[string]any)
	if assets["logo_light"] == nil {
		t.Fatalf("the theme does not list the logo: %v", theme)
	}

	// An executable is not a logo.
	bad := admin.do(t, h.internal, http.MethodPut, "/api/v1/branding/assets/logo_dark",
		[]byte("MZ\x90\x00 this is not an image"), map[string]string{"Content-Type": "image/png"})
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an executable was accepted: %d %s", bad.Code, bad.Body.String())
	}

	// Neither is an SVG that runs script.
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	bad = admin.do(t, h.internal, http.MethodPut, "/api/v1/branding/assets/logo_dark", svg,
		map[string]string{"Content-Type": "image/svg+xml"})
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an SVG with script was accepted: %d %s", bad.Code, bad.Body.String())
	}

	if rec := admin.do(t, h.internal, http.MethodDelete, "/api/v1/branding/assets/logo_light", nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete asset: %d", rec.Code)
	}
	if rec := do(t, h.public, http.MethodGet, "/branding/logo_light", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("a deleted asset is still served: %d", rec.Code)
	}
}

func TestBrandingIsAdministratorOnly(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/users", jsonBody(t, map[string]any{
		"email": "manager@acme.example", "role": "manager", "password": testOtherPassword, "invite": false,
	}), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create manager: %d %s", rec.Code, rec.Body.String())
	}
	manager := h.signInAs(t, "manager@acme.example", testOtherPassword)

	// A manager runs the users; the brand of the whole instance does not
	// belong to them.
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/branding/admin"},
		{http.MethodPut, "/api/v1/branding/admin"},
		{http.MethodDelete, "/api/v1/branding/admin"},
		{http.MethodPost, "/api/v1/branding/test-email"},
	} {
		rec := manager.do(t, h.internal, probe.method, probe.path, []byte("{}"), nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as a manager returned %d, want 403", probe.method, probe.path, rec.Code)
		}
	}

	// And none of it is reachable from the public listener at all.
	h2 := newHarness(t, func(c *config.Config) { c.Server.PublicListen = "0.0.0.0:8081" })
	for _, path := range []string{"/api/v1/branding/admin", "/api/v1/branding/test-email"} {
		if rec := do(t, h2.public, http.MethodGet, path, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s on the public listener returned %d, want 404", path, rec.Code)
		}
	}
}

func TestTestEmailNeedsSMTP(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/branding/test-email",
		jsonBody(t, map[string]string{"to": "someone@acme.example"}), nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 without SMTP: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "peek.toml") {
		t.Fatalf("the answer does not say how to fix it: %s", rec.Body.String())
	}
}
