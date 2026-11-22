package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/store"
)

// issueToken signs in as an administrator and mints a token with the given
// scopes, returning its clear text and the session that made it — the
// bootstrap page only works once, so a test that needs both must share it.
func (h *harness) issueToken(t *testing.T, scopes []string) (string, *session) {
	t.Helper()
	return h.issueTokenAs(t, h.signIn(t), scopes)
}

func (h *harness) issueTokenAs(t *testing.T, admin *session, scopes []string) (string, *session) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name":   "script de déploiement",
		"scopes": scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/tokens", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token returned %d: %s", rec.Code, rec.Body.String())
	}
	secret, _ := decodeBody(t, rec)["token"].(string)
	if !strings.HasPrefix(secret, "peek_") {
		t.Fatalf("token does not carry the peek_ prefix: %q", secret)
	}
	return secret, admin
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestTokenCreatesSecrets(t *testing.T) {
	h := newHarness(t, nil)
	token, _ := h.issueToken(t, []string{store.ScopeSecretsWrite})

	c := newClient(t, "", "déployé par un script")
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), bearer(token))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with a token returned %d: %s", rec.Code, rec.Body.String())
	}

	// And the secret reads back normally: a token-created secret is an
	// ordinary secret.
	reveal := h.reveal(t, h.public, c, c.keys.ReadToken)
	if reveal.Code != http.StatusOK {
		t.Errorf("reveal returned %d", reveal.Code)
	}
}

func TestTokenScopesAreEnforced(t *testing.T) {
	h := newHarness(t, nil)
	writeOnly, admin := h.issueToken(t, []string{store.ScopeSecretsWrite})

	c := newClient(t, "", "x")
	h.create(t, c, nil)

	// secrets:write does not include reading a receipt or burning.
	body, _ := json.Marshal(map[string]string{"receipt_token": "x"})
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets/"+c.id+"/burn", body, bearer(writeOnly))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("burn with a write-only token returned %d: %s", rec.Code, rec.Body.String())
	}
	if code := decodeBody(t, rec)["error"].(map[string]any)["code"]; code != "missing_scope" {
		t.Errorf("error code = %v, want missing_scope", code)
	}

	// Nor reading the audit trail.
	rec = do(t, h.internal, http.MethodGet, "/api/v1/audit", nil, bearer(writeOnly))
	if rec.Code != http.StatusForbidden {
		t.Errorf("audit with a write-only token returned %d", rec.Code)
	}

	// A token with the right scope gets through.
	reader, _ := h.issueTokenAs(t, admin, []string{store.ScopeAuditRead})
	rec = do(t, h.internal, http.MethodGet, "/api/v1/audit", nil, bearer(reader))
	if rec.Code != http.StatusOK {
		t.Errorf("audit with an audit:read token returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenCannotReachTheAccountSurface(t *testing.T) {
	h := newHarness(t, nil)
	token, _ := h.issueToken(t, []string{store.ScopeSecretsWrite, store.ScopeSecretsManage,
		store.ScopeAuditRead, store.ScopeInstanceRead})

	// Even with every scope: a token is for sending secrets, not for changing
	// credentials, and above all not for minting another token.
	cases := []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, "/api/v1/auth/tokens", nil},
		{http.MethodPost, "/api/v1/auth/tokens", []byte(`{"name":"x","scopes":["secrets:write"]}`)},
		{http.MethodPost, "/api/v1/auth/password", []byte(`{"current":"x","next":"y"}`)},
		{http.MethodGet, "/api/v1/auth/sessions", nil},
		{http.MethodPost, "/api/v1/auth/totp/start", nil},
		{http.MethodGet, "/api/v1/users", nil},
		{http.MethodPut, "/api/v1/branding/admin", []byte(`{}`)},
	}
	for _, c := range cases {
		rec := do(t, h.internal, c.method, c.path, c.body, bearer(token))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with a token returned %d, want 403", c.method, c.path, rec.Code)
		}
	}
}

func TestTokenRejectedWhenUnknownOrRevoked(t *testing.T) {
	h := newHarness(t, nil)
	token, admin := h.issueToken(t, []string{store.ScopeSecretsWrite})
	id, _, err := accounts.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}

	c := newClient(t, "", "x")
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), bearer(token))
	if rec.Code != http.StatusCreated {
		t.Fatalf("the token did not work before revocation: %d", rec.Code)
	}

	rec = admin.do(t, h.internal, http.MethodDelete, "/api/v1/auth/tokens/"+id, nil, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke returned %d: %s", rec.Code, rec.Body.String())
	}

	other := newClient(t, "", "y")
	rec = do(t, h.internal, http.MethodPost, "/api/v1/secrets", other.createBody(t, nil), bearer(token))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token returned %d, want 401", rec.Code)
	}

	// Garbage, a wrong prefix and a well-formed unknown token all answer the
	// same: a caller learns only that it does not work.
	for _, bad := range []string{
		"not-a-token",
		"peek_short_x",
		"peek_" + strings.Repeat("A", 22) + "_" + strings.Repeat("B", 43),
	} {
		rec = do(t, h.internal, http.MethodPost, "/api/v1/secrets", other.createBody(t, nil), bearer(bad))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q returned %d, want 401", bad, rec.Code)
		}
	}
}

func TestTokenNeedsNoCSRF(t *testing.T) {
	h := newHarness(t, nil)
	token, _ := h.issueToken(t, []string{store.ScopeSecretsWrite})

	// No cookie, so no cross-site request to forge, so no CSRF header. A
	// script would have no way to produce one.
	c := newClient(t, "", "x")
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), bearer(token))
	if rec.Code != http.StatusCreated {
		t.Fatalf("a token call without a CSRF header returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenIsInternalOnly(t *testing.T) {
	h := newHarness(t, nil)
	token, _ := h.issueToken(t, []string{store.ScopeSecretsWrite})
	c := newClient(t, "", "x")
	rec := do(t, h.public, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), bearer(token))
	if rec.Code != http.StatusNotFound {
		t.Errorf("creating on the public listener with a token returned %d", rec.Code)
	}
}

func TestTokenCreationRefusesUnknownScope(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)
	for _, scopes := range [][]string{{}, {"everything"}, {"secrets:write", "root"}} {
		body, _ := json.Marshal(map[string]any{"name": "x", "scopes": scopes})
		rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/tokens", body, nil)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("scopes %v returned %d, want 422", scopes, rec.Code)
		}
	}
}

func TestTokenListingHidesTheSecret(t *testing.T) {
	h := newHarness(t, nil)
	secret, admin := h.issueToken(t, []string{store.ScopeSecretsWrite})

	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/auth/tokens", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Error("the listing echoed the token's clear text")
	}
	body := decodeBody(t, rec)
	list, ok := body["tokens"].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("no token in the listing: %v", body)
	}
	first := list[0].(map[string]any)
	if _, leaked := first["token"]; leaked {
		t.Error("a listed token carries a clear-text field")
	}
	if first["name"] != "script de déploiement" {
		t.Errorf("name = %v", first["name"])
	}
}
