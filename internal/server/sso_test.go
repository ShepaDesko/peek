package server_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/auth"
	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// A fake identity provider.
//
// It serves a real discovery document, a real JWKS, and a real RS256-signed ID
// token, so the test exercises the whole verification path rather than a mock
// of it. Everything the tests want to break — the nonce, the audience, the
// issuer, the signing key, the expiry — is a field on this struct.

type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	// Knobs the tests turn.
	clientID string
	subject  string
	email    string
	verified *bool
	name     string
	groups   []string
	// Overrides. Zero means "behave correctly".
	issuerOverride   string
	audienceOverride []string
	nonceOverride    string
	expiresIn        time.Duration
	signWithOtherKey bool
	alg              string
	omitEmail        bool
	claimOverflow    bool

	// Recorded from the authorization request.
	lastQuery  url.Values
	lastCode   string
	codes      map[string]string // code -> nonce
	tokenCalls int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{
		key:      key,
		clientID: "peek-test-client",
		subject:  "00000000-1111-2222-3333-444444444444",
		email:    "alice@acme.test",
		name:     "Alice Martin",
		codes:    map[string]string{},
		alg:      "RS256",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.discovery)
	mux.HandleFunc("/keys", idp.jwks)
	mux.HandleFunc("/authorize", idp.authorize)
	mux.HandleFunc("/token", idp.token)
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (f *fakeIdP) issuer() string { return f.server.URL }

func (f *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeTestJSON(w, map[string]any{
		"issuer":                                f.issuer(),
		"authorization_endpoint":                f.issuer() + "/authorize",
		"token_endpoint":                        f.issuer() + "/token",
		"jwks_uri":                              f.issuer() + "/keys",
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (f *fakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := f.key.Public().(*rsa.PublicKey)
	writeTestJSON(w, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"kid": "test-key-1",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize records what Peek asked for and hands back a code.
func (f *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	f.lastQuery = r.URL.Query()
	code := "code-" + f.lastQuery.Get("state")[:8]
	f.lastCode = code
	f.codes[code] = f.lastQuery.Get("nonce")
	redirect := f.lastQuery.Get("redirect_uri") +
		"?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(f.lastQuery.Get("state"))
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	f.tokenCalls++
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	nonce, ok := f.codes[code]
	if !ok {
		writeTestJSON(w, map[string]any{"error": "invalid_grant"})
		return
	}
	delete(f.codes, code)

	// PKCE: the verifier must hash to the challenge the authorization request
	// carried. A provider that does not check this is a provider that makes
	// PKCE decorative, so the fake one checks.
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != f.lastQuery.Get("code_challenge") {
		writeTestJSON(w, map[string]any{"error": "invalid_grant", "error_description": "PKCE mismatch"})
		return
	}
	if r.PostForm.Get("client_secret") == "" {
		writeTestJSON(w, map[string]any{"error": "invalid_client"})
		return
	}

	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	writeTestJSON(w, map[string]any{
		"token_type":   "Bearer",
		"expires_in":   3600,
		"access_token": "fake-access-token",
		"id_token":     f.idToken(nonce),
	})
}

func (f *fakeIdP) idToken(nonce string) string {
	now := time.Now()
	lifetime := f.expiresIn
	if lifetime == 0 {
		lifetime = time.Hour
	}
	issuer := f.issuer()
	if f.issuerOverride != "" {
		issuer = f.issuerOverride
	}
	var audience any = f.clientID
	if f.audienceOverride != nil {
		audience = f.audienceOverride
	}
	claims := map[string]any{
		"iss":   issuer,
		"aud":   audience,
		"sub":   f.subject,
		"iat":   now.Unix(),
		"exp":   now.Add(lifetime).Unix(),
		"nonce": nonce,
		"name":  f.name,
	}
	if !f.omitEmail {
		claims["email"] = f.email
	}
	if f.verified != nil {
		claims["email_verified"] = *f.verified
	}
	if len(f.groups) > 0 {
		claims["groups"] = f.groups
	}
	if f.claimOverflow {
		claims["_claim_names"] = map[string]string{"groups": "src1"}
		delete(claims, "groups")
	}

	header, _ := json.Marshal(map[string]string{"alg": f.alg, "typ": "JWT", "kid": "test-key-1"})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	key := f.key
	if f.signWithOtherKey {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		key = other
	}
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeTestJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------------------
// The flow, end to end
// ---------------------------------------------------------------------------

// ssoHarness wires a server to the fake provider and follows the redirects by
// hand, keeping the cookies, exactly as a browser would.
type ssoHarness struct {
	*harness
	idp     *fakeIdP
	cookies map[string]string
}

func newSSOHarness(t *testing.T, tweak func(*config.SSO)) *ssoHarness {
	t.Helper()
	idp := newFakeIdP(t)
	h := newHarness(t, func(cfg *config.Config) {
		cfg.SSO = config.SSO{
			Enabled:         true,
			Provider:        "generic",
			DisplayName:     "ACME Directory",
			Issuer:          idp.issuer(),
			ClientID:        idp.clientID,
			ClientSecret:    "a-client-secret",
			Discovery:       true,
			Provision:       true,
			DefaultRole:     store.RoleMember,
			SyncRoleOnLogin: true,
		}
		if tweak != nil {
			tweak(&cfg.SSO)
		}
	})
	return &ssoHarness{harness: h, idp: idp, cookies: map[string]string{}}
}

// signInThroughSSO walks the whole flow and returns the final redirect target
// plus the session cookie, if one was set.
func (s *ssoHarness) signInThroughSSO(t *testing.T) (string, map[string]string) {
	t.Helper()

	// 1. The browser asks Peek to start.
	rec := s.get(t, "/auth/sso?return=/create")
	if rec.Code != http.StatusFound {
		t.Fatalf("/auth/sso returned %d: %s", rec.Code, rec.Body.String())
	}
	target := rec.Header().Get("Location")
	if !strings.HasPrefix(target, s.idp.issuer()+"/authorize") {
		// A redirect back to /login means Peek refused before leaving.
		return target, s.cookies
	}

	// 2. The provider authenticates and redirects back. Call it directly;
	// what matters is the query it hands to the callback.
	idpReq := httptest.NewRequest(http.MethodGet, target, nil)
	idpRec := httptest.NewRecorder()
	s.idp.server.Config.Handler.ServeHTTP(idpRec, idpReq)
	if idpRec.Code != http.StatusFound {
		t.Fatalf("the provider answered %d", idpRec.Code)
	}
	back, err := url.Parse(idpRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	// 3. The callback, with the cookies the start set.
	rec = s.get(t, back.Path+"?"+back.RawQuery)
	if rec.Code != http.StatusFound {
		t.Fatalf("the callback returned %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location"), s.cookies
}

// get issues a GET carrying the cookies collected so far, and collects any new
// ones from the response.
func (s *ssoHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = "192.0.2.10:54321"
	for name, value := range s.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	s.internal.ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(s.cookies, cookie.Name)
			continue
		}
		s.cookies[cookie.Name] = cookie.Value
	}
	return rec
}

func TestSSOProvisionsAnAccountAndSignsIn(t *testing.T) {
	h := newSSOHarness(t, nil)

	// The sign-in page learns what to show without authenticating.
	rec := do(t, h.internal, http.MethodGet, "/api/v1/auth/sso", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/auth/sso returned %d", rec.Code)
	}
	info := decodeBody(t, rec)
	if info["enabled"] != true || info["label"] != "ACME Directory" || info["required"] != false {
		t.Errorf("sso info = %v", info)
	}

	target, cookies := h.signInThroughSSO(t)
	if target != "/create" {
		t.Fatalf("the callback redirected to %q, want the requested return path", target)
	}
	if cookies["peek_session"] == "" {
		t.Fatal("no session cookie was set")
	}
	// The one-time flow cookie is gone: an attempt is single use.
	if cookies["peek_sso"] != "" {
		t.Error("the sign-in attempt cookie survived the callback")
	}

	// The authorization request carried what it should.
	q := h.idp.lastQuery
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Error("the authorization request did not use PKCE")
	}
	if q.Get("nonce") == "" || q.Get("state") == "" {
		t.Error("the authorization request carried no nonce or no state")
	}
	if !strings.HasSuffix(q.Get("redirect_uri"), "/auth/sso/callback") {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}

	// The account exists, with the default role and no password at all.
	user, err := h.store.UserByEmail(t.Context(), store.DefaultOrgID, "alice@acme.test")
	if err != nil {
		t.Fatalf("the account was not provisioned: %v", err)
	}
	if user.Role != store.RoleMember || user.DisplayName != "Alice Martin" {
		t.Errorf("user = %+v", user)
	}
	if user.PasswordHash != "" {
		t.Error("a provisioned account has a password hash; there is nothing to guess and it should be empty")
	}
	if user.SSOSubject != h.idp.subject || user.SSOIssuer != h.idp.issuer() {
		t.Errorf("the account is not linked to the directory identity: %+v", user)
	}

	// And the session works.
	sess := &session{cookies: cookies, csrf: cookies["peek_csrf"]}
	if rec := sess.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("/auth/me with the SSO session returned %d: %s", rec.Code, rec.Body.String())
	}

	// Audit: one sso login, naming neither a token nor a claim.
	events, err := h.store.ListAudit(t.Context(), store.AuditFilter{Event: store.EventSSOLogin})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("audit holds %d sso logins", len(events))
	}
	if events[0].Detail["account"] != "provisioned" {
		t.Errorf("audit detail = %v", events[0].Detail)
	}
}

func TestSSOSecondSignInReusesTheAccount(t *testing.T) {
	h := newSSOHarness(t, nil)
	h.signInThroughSSO(t)

	// The address changed at the provider; the subject did not. The account
	// must follow the subject, not grow a second row.
	h.idp.email = "alice.martin@acme.test"
	h.cookies = map[string]string{}
	if target, _ := h.signInThroughSSO(t); target != "/create" {
		t.Fatalf("the second sign-in went to %q", target)
	}

	users, err := h.store.ListUsers(t.Context(), store.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("%d accounts after two sign-ins by the same person", len(users))
	}
	if users[0].Email != "alice.martin@acme.test" {
		t.Errorf("the address did not follow the directory: %q", users[0].Email)
	}
}

func TestSSOMapsGroupsToRoles(t *testing.T) {
	h := newSSOHarness(t, func(sso *config.SSO) {
		sso.AdminGroups = []string{"peek-admins"}
		sso.ManagerGroups = []string{"peek-managers"}
		sso.AuditorGroups = []string{"peek-auditors"}
	})
	// In both the manager and the admin group: the strongest wins, and the
	// answer must not depend on the order of the lists.
	h.idp.groups = []string{"peek-managers", "peek-admins", "unrelated"}

	h.signInThroughSSO(t)
	user, err := h.store.UserByEmail(t.Context(), store.DefaultOrgID, "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != store.RoleAdmin {
		t.Fatalf("role = %q, want admin: the strongest mapped group should win", user.Role)
	}

	// Demoted in the directory: the next sign-in follows it.
	h.idp.groups = []string{"peek-auditors"}
	h.cookies = map[string]string{}
	h.signInThroughSSO(t)
	user, _ = h.store.UserByEmail(t.Context(), store.DefaultOrgID, "alice@acme.test")
	if user.Role != store.RoleAuditor {
		t.Errorf("role = %q after a directory change, want auditor", user.Role)
	}
}

func TestSSORequireGroupRefusesTheUnmapped(t *testing.T) {
	h := newSSOHarness(t, func(sso *config.SSO) {
		sso.AdminGroups = []string{"peek-admins"}
		sso.RequireGroup = true
	})
	h.idp.groups = []string{"some-other-group"}

	target, cookies := h.signInThroughSSO(t)
	if !strings.Contains(target, "sso_error=no_group") {
		t.Fatalf("the callback redirected to %q, want an explicit no_group refusal", target)
	}
	if cookies["peek_session"] != "" {
		t.Error("a session was opened for a user in no mapped group")
	}
	if n, _ := h.store.CountUsers(t.Context(), store.DefaultOrgID); n != 0 {
		t.Errorf("%d accounts were provisioned for a refused sign-in", n)
	}
}

func TestSSOAllowedDomains(t *testing.T) {
	h := newSSOHarness(t, func(sso *config.SSO) {
		sso.AllowedDomains = []string{"acme.com"}
	})
	if target, _ := h.signInThroughSSO(t); !strings.Contains(target, "sso_error=domain") {
		t.Fatalf("a foreign domain was not refused: %q", target)
	}
	if n, _ := h.store.CountUsers(t.Context(), store.DefaultOrgID); n != 0 {
		t.Error("an account was provisioned for a refused domain")
	}
}

func TestSSOWithoutProvisioningNeedsAnAccount(t *testing.T) {
	h := newSSOHarness(t, func(sso *config.SSO) { sso.Provision = false })

	if target, _ := h.signInThroughSSO(t); !strings.Contains(target, "sso_error=no_account") {
		t.Fatalf("redirected to %q, want no_account", target)
	}

	// Create the account locally, and now the same identity links to it.
	if _, err := h.store.CreateUser(t.Context(), store.User{
		Email: "alice@acme.test", DisplayName: "Alice", Role: store.RoleManager,
	}); err != nil {
		t.Fatal(err)
	}
	h.cookies = map[string]string{}
	target, cookies := h.signInThroughSSO(t)
	if target != "/create" || cookies["peek_session"] == "" {
		t.Fatalf("the link to an existing account did not sign in: %q", target)
	}
	user, _ := h.store.UserByEmail(t.Context(), store.DefaultOrgID, "alice@acme.test")
	if user.SSOSubject != h.idp.subject {
		t.Error("the existing account was not linked to the directory identity")
	}
	// Linking must not quietly change a role the operator set locally.
	if user.Role != store.RoleManager {
		t.Errorf("role = %q, want the local manager role to survive linking", user.Role)
	}
}

// TestSSOWillNotLinkAnUnverifiedAddress is the account-takeover guard: a
// provider that lets a user type any address must not hand them somebody
// else's existing account.
func TestSSOWillNotLinkAnUnverifiedAddress(t *testing.T) {
	h := newSSOHarness(t, nil)
	unverified := false
	h.idp.verified = &unverified

	if _, err := h.store.CreateUser(t.Context(), store.User{
		Email: "alice@acme.test", DisplayName: "The real Alice", Role: store.RoleAdmin,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}); err != nil {
		t.Fatal(err)
	}

	target, cookies := h.signInThroughSSO(t)
	if !strings.Contains(target, "sso_error=claimed") {
		t.Fatalf("an unverified address linked to an existing account: %q", target)
	}
	if cookies["peek_session"] != "" {
		t.Fatal("a session was opened for an unverified address matching an existing account")
	}
	user, _ := h.store.UserByEmail(t.Context(), store.DefaultOrgID, "alice@acme.test")
	if user.SSOSubject != "" {
		t.Error("the existing account was linked anyway")
	}
}

func TestSSORejectsATamperedState(t *testing.T) {
	h := newSSOHarness(t, nil)

	rec := h.get(t, "/auth/sso")
	target := rec.Header().Get("Location")
	idpReq := httptest.NewRequest(http.MethodGet, target, nil)
	idpRec := httptest.NewRecorder()
	h.idp.server.Config.Handler.ServeHTTP(idpRec, idpReq)
	back, _ := url.Parse(idpRec.Header().Get("Location"))

	q := back.Query()
	q.Set("state", "not-the-state-we-issued")
	rec = h.get(t, back.Path+"?"+q.Encode())
	if !strings.Contains(rec.Header().Get("Location"), "sso_error=state") {
		t.Fatalf("a forged state was accepted: %q", rec.Header().Get("Location"))
	}
	if h.cookies["peek_session"] != "" {
		t.Error("a session was opened on a state mismatch")
	}
}

func TestSSOCallbackWithoutAnAttempt(t *testing.T) {
	h := newSSOHarness(t, nil)
	// A bookmarked callback URL: no cookie, so there is no attempt to finish.
	rec := h.get(t, "/auth/sso/callback?code=whatever&state=whatever")
	if !strings.Contains(rec.Header().Get("Location"), "sso_error=expired") {
		t.Fatalf("location = %q", rec.Header().Get("Location"))
	}
	if h.idp.tokenCalls != 0 {
		t.Error("the token endpoint was called without a verified attempt")
	}
}

func TestSSORejectsABadAssertion(t *testing.T) {
	cases := []struct {
		name   string
		broken func(*fakeIdP)
	}{
		{"another signing key", func(f *fakeIdP) { f.signWithOtherKey = true }},
		{"another issuer", func(f *fakeIdP) { f.issuerOverride = "https://evil.example" }},
		{"another audience", func(f *fakeIdP) { f.audienceOverride = []string{"someone-else"} }},
		{"a replayed nonce", func(f *fakeIdP) { f.nonceOverride = "a-nonce-from-another-attempt" }},
		{"an expired token", func(f *fakeIdP) { f.expiresIn = -2 * time.Hour }},
		{"an HMAC signature", func(f *fakeIdP) { f.alg = "HS256" }},
		{"alg none", func(f *fakeIdP) { f.alg = "none" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSSOHarness(t, nil)
			tc.broken(h.idp)

			target, cookies := h.signInThroughSSO(t)
			if !strings.Contains(target, "sso_error=") {
				t.Fatalf("%s was accepted; the callback went to %q", tc.name, target)
			}
			if cookies["peek_session"] != "" {
				t.Fatalf("%s opened a session", tc.name)
			}
			if n, _ := h.store.CountUsers(t.Context(), store.DefaultOrgID); n != 0 {
				t.Errorf("%s provisioned an account", tc.name)
			}
		})
	}
}

// TestSSOReturnPathCannotLeaveTheInstance is the open-redirect guard. A
// sign-in flow that can be made to land on another site is a phishing
// primitive: the victim really did sign in, and really was redirected.
func TestSSOReturnPathCannotLeaveTheInstance(t *testing.T) {
	for _, hostile := range []string{
		"https://evil.example/steal",
		"//evil.example/steal",
		"/\\evil.example",
		"http:/evil.example",
		"/create\r\nSet-Cookie: x=1",
	} {
		h := newSSOHarness(t, nil)
		rec := h.get(t, "/auth/sso?return="+url.QueryEscape(hostile))
		if rec.Code != http.StatusFound {
			t.Fatalf("%q: start returned %d", hostile, rec.Code)
		}
		idpReq := httptest.NewRequest(http.MethodGet, rec.Header().Get("Location"), nil)
		idpRec := httptest.NewRecorder()
		h.idp.server.Config.Handler.ServeHTTP(idpRec, idpReq)
		back, _ := url.Parse(idpRec.Header().Get("Location"))

		rec = h.get(t, back.Path+"?"+back.RawQuery)
		location := rec.Header().Get("Location")
		if strings.Contains(location, "evil.example") {
			t.Errorf("%q survived into the final redirect: %q", hostile, location)
		}
		if location != "/" && location != "/create" {
			t.Errorf("%q produced an unexpected redirect: %q", hostile, location)
		}
	}
}

// TestSSORequiredRefusesLocalCredentials: "required" that only hides the form
// is not required.
func TestSSORequiredRefusesLocalCredentials(t *testing.T) {
	h := newSSOHarness(t, func(sso *config.SSO) {
		sso.Required = true
		sso.PasswordExempt = []string{"breakglass@acme.test"}
	})

	info := decodeBody(t, do(t, h.internal, http.MethodGet, "/api/v1/auth/sso", nil, nil))
	if info["required"] != true {
		t.Errorf("the sign-in page is not told that local sign-in is refused: %v", info)
	}

	// An account with a password, not on the exempt list.
	hash, err := auth.HashPassword("the-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateUser(t.Context(), store.User{
		Email: "bob@acme.test", DisplayName: "Bob", Role: store.RoleAdmin, PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateUser(t.Context(), store.User{
		Email: "breakglass@acme.test", DisplayName: "Break glass", Role: store.RoleAdmin, PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}

	body := jsonBody(t, map[string]string{"email": "bob@acme.test", "password": "the-password"})
	rec := do(t, h.internal, http.MethodPost, "/api/v1/auth/login", body, nil)
	if rec.Code != http.StatusForbidden || decodeBody(t, rec)["error"].(map[string]any)["code"] != "sso_required" {
		t.Fatalf("a password sign-in was not refused: %d %s", rec.Code, rec.Body.String())
	}

	// The break-glass account still works, which is the whole point of
	// naming it: an instance whose provider is down must stay repairable.
	body = jsonBody(t, map[string]string{"email": "breakglass@acme.test", "password": "the-password"})
	if rec := do(t, h.internal, http.MethodPost, "/api/v1/auth/login", body, nil); rec.Code != http.StatusOK {
		t.Fatalf("the exempt account could not sign in: %d %s", rec.Code, rec.Body.String())
	}

	// And the refusal is in the audit trail with its reason.
	events, _ := h.store.ListAudit(t.Context(), store.AuditFilter{Event: store.EventLoginFailed})
	if len(events) == 0 || events[0].Detail["reason"] != "sso_required" {
		t.Errorf("the refusal is not in the audit trail: %+v", events)
	}
}

// TestSSOGroupOverflowIsNamed: Entra replaces the group list with a pointer to
// Graph past about two hundred groups. Seeing no groups and handing out the
// default role would be the dangerous reading of that.
func TestSSOGroupOverflowIsRefusedNotIgnored(t *testing.T) {
	h := newSSOHarness(t, func(sso *config.SSO) {
		sso.AdminGroups = []string{"peek-admins"}
	})
	h.idp.claimOverflow = true

	target, cookies := h.signInThroughSSO(t)
	if !strings.Contains(target, "sso_error=token") {
		t.Fatalf("a group overflow claim was not refused: %q", target)
	}
	if cookies["peek_session"] != "" {
		t.Error("a session was opened from a token with no readable group list")
	}
}

func TestSSOIsInternalListenerOnly(t *testing.T) {
	h := newSSOHarness(t, nil)
	for _, path := range []string{"/auth/sso", "/auth/sso/callback", "/api/v1/auth/sso"} {
		rec := do(t, h.public, http.MethodGet, path, nil, nil)
		// The SPA catch-all serves the interface on an unknown path, so what
		// matters is that it is not the handler: no redirect to the provider.
		if location := rec.Header().Get("Location"); strings.Contains(location, h.idp.issuer()) {
			t.Errorf("%s on the public listener redirected to the provider", path)
		}
		if rec.Code == http.StatusFound {
			t.Errorf("%s on the public listener answered %d", path, rec.Code)
		}
	}
}

// TestSSODisabledSaysSo: half a feature must refuse loudly.
func TestSSODisabledSaysSo(t *testing.T) {
	h := newHarness(t, nil)
	info := decodeBody(t, do(t, h.internal, http.MethodGet, "/api/v1/auth/sso", nil, nil))
	if info["enabled"] != false {
		t.Errorf("sso info = %v", info)
	}
	if info["start_url"] != nil {
		t.Error("a disabled provider still advertises a start URL")
	}
	rec := do(t, h.internal, http.MethodGet, "/auth/sso", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("/auth/sso with nothing configured returned %d, want 404", rec.Code)
	}
}
