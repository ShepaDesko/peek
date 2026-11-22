package server_test

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// TestOpenAPICoversEveryRoute is the reason the document is generated from the
// router rather than written beside it.
//
// A route added without a description fails here, by name. A description left
// behind after a route is removed fails here too. Neither can be "fixed later",
// because the document is built at request time from the same table.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	h := newHarness(t, nil)

	doc, err := h.srv.OpenAPI()
	if err != nil {
		// The builder itself reports which routes are undescribed.
		t.Fatalf("the document does not cover the router: %v", err)
	}

	routes, err := h.srv.RouteKeys()
	if err != nil {
		t.Fatal(err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("no paths in the document")
	}

	described := map[string]bool{}
	for route, item := range paths {
		methods, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("path %s is not an object", route)
		}
		for method := range methods {
			if method == "parameters" {
				continue
			}
			described[strings.ToUpper(method)+" "+route] = true
		}
	}

	var missing []string
	for _, key := range routes {
		if !described[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("routes with no OpenAPI description:\n  %s", strings.Join(missing, "\n  "))
	}

	live := map[string]bool{}
	for _, key := range routes {
		live[key] = true
	}
	var orphaned []string
	for key := range described {
		if !live[key] {
			orphaned = append(orphaned, key)
		}
	}
	if len(orphaned) > 0 {
		sort.Strings(orphaned)
		t.Errorf("OpenAPI describes routes that no longer exist:\n  %s", strings.Join(orphaned, "\n  "))
	}
}

// TestOpenAPIIsWellFormed checks the shape a client generator relies on, and
// that every $ref resolves — a dangling reference breaks the generators
// silently rather than loudly.
func TestOpenAPIIsWellFormed(t *testing.T) {
	h := newHarness(t, nil)
	doc, err := h.srv.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}

	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v", doc["openapi"])
	}
	info := doc["info"].(map[string]any)
	if info["title"] != "Peek" || info["version"] == "" {
		t.Errorf("info = %v", info)
	}

	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	if len(schemas) < 10 {
		t.Errorf("only %d schemas", len(schemas))
	}

	// Walk the whole document and resolve every reference.
	var refs []string
	var walk func(v any)
	walk = func(v any) {
		switch value := v.(type) {
		case map[string]any:
			for k, inner := range value {
				if k == "$ref" {
					if ref, ok := inner.(string); ok {
						refs = append(refs, ref)
					}
					continue
				}
				walk(inner)
			}
		case []any:
			for _, inner := range value {
				walk(inner)
			}
		}
	}
	walk(doc)
	if len(refs) == 0 {
		t.Fatal("no $ref at all: the schemas are not wired to the operations")
	}
	for _, ref := range refs {
		name := strings.TrimPrefix(ref, "#/components/schemas/")
		if name == ref {
			t.Errorf("unexpected reference form %q", ref)
			continue
		}
		if _, ok := schemas[name]; !ok {
			t.Errorf("dangling reference %q", ref)
		}
	}

	// Every operation says where it is served and how to authenticate: that
	// prose is the difference between a route list and a usable description.
	for route, item := range doc["paths"].(map[string]any) {
		for method, op := range item.(map[string]any) {
			if method == "parameters" {
				continue
			}
			operation := op.(map[string]any)
			for _, field := range []string{"summary", "description", "responses", "tags"} {
				if operation[field] == nil {
					t.Errorf("%s %s has no %s", strings.ToUpper(method), route, field)
				}
			}
			desc := operation["description"].(string)
			if !strings.Contains(desc, "listener") {
				t.Errorf("%s %s does not say which listener serves it", strings.ToUpper(method), route)
			}
		}
	}
}

func TestOpenAPIIsServedAndInternalOnly(t *testing.T) {
	h := newHarness(t, nil)

	rec := do(t, h.internal, http.MethodGet, "/api/v1/openapi.json", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json returned %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the served document is not JSON: %v", err)
	}
	if doc["paths"] == nil {
		t.Error("the served document has no paths")
	}

	// It describes the internal surface, so it stays on the internal listener.
	if rec := do(t, h.public, http.MethodGet, "/api/v1/openapi.json", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("openapi.json on the public listener returned %d", rec.Code)
	}
}
