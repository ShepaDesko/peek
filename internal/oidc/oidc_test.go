package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// The other half of the provider is HTTP: discovery, the token exchange and
// the key set. Each of those is a place where a wrong answer from the network
// must not become a sign-in, so each gets a fake provider to answer wrongly.

// fakeIdP is an identity provider that answers on localhost.
type fakeIdP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	kid  string
	hits struct {
		discovery atomic.Int64
		jwks      atomic.Int64
		token     atomic.Int64
	}

	// Knobs the tests turn.
	issuerOverride string
	omitTokenURL   bool
	authorizeURL   string
	tokenStatus    int
	tokenBody      string
	idToken        func(t *testing.T, idp *fakeIdP) string
	lastTokenForm  url.Values
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{key: rsaKey(t, 2048), kid: "idp-1"}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.hits.discovery.Add(1)
		issuer := idp.srv.URL
		if idp.issuerOverride != "" {
			issuer = idp.issuerOverride
		}
		authorize := idp.srv.URL + "/authorize"
		if idp.authorizeURL != "" {
			authorize = idp.authorizeURL
		}
		doc := map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": authorize,
			"jwks_uri":               idp.srv.URL + "/jwks",
			"userinfo_endpoint":      idp.srv.URL + "/userinfo",
		}
		if !idp.omitTokenURL {
			doc["token_endpoint"] = idp.srv.URL + "/token"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.hits.jwks.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keySet{Keys: []jsonWebKey{rsaJWK(idp.kid, &idp.key.PublicKey)}})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.hits.token.Add(1)
		_ = r.ParseForm()
		idp.lastTokenForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		if idp.tokenBody != "" {
			if idp.tokenStatus != 0 {
				w.WriteHeader(idp.tokenStatus)
			}
			_, _ = w.Write([]byte(idp.tokenBody))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
			"id_token": idp.idToken(t, idp),
		})
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// claims returns a claim set this fake provider would issue.
func (idp *fakeIdP) claims() map[string]any {
	set := claims()
	set["iss"] = idp.srv.URL
	return set
}

func (idp *fakeIdP) sign(t *testing.T, set map[string]any) string {
	t.Helper()
	return signRS256(t, idp.key, idp.kid, set)
}

// provider builds a Provider pointed at this fake, with discovery on and no
// key set cached.
func (idp *fakeIdP) provider(t *testing.T, tweak ...func(*config.SSO)) *Provider {
	t.Helper()
	cfg := config.SSO{
		Enabled: true, Discovery: true,
		Issuer: idp.srv.URL, ClientID: testClientID, ClientSecret: "s3cret",
	}
	for _, f := range tweak {
		f(&cfg)
	}
	p, err := New(cfg, discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestDiscoveryReadsEndpointsAndCachesThem(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.provider(t)

	meta, err := p.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.TokenEndpoint != idp.srv.URL+"/token" || meta.JWKSURI != idp.srv.URL+"/jwks" {
		t.Errorf("endpoints = %+v", meta)
	}
	if _, err := p.Metadata(context.Background()); err != nil {
		t.Fatalf("Metadata again: %v", err)
	}
	if got := idp.hits.discovery.Load(); got != 1 {
		t.Errorf("the discovery document was read %d times; it is cached for %s", got, discoveryTTL)
	}
}

// A provider that serves somebody else's discovery document would redirect
// the whole flow somewhere Peek was never configured to trust.
func TestDiscoveryRefusesIssuerMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	idp.issuerOverride = "https://login.attacker.example/v2.0"
	p := idp.provider(t)

	_, err := p.Metadata(context.Background())
	if err == nil {
		t.Fatal("a discovery document naming another issuer was accepted")
	}
	if !errors.Is(err, ErrProvider) {
		t.Errorf("error does not wrap ErrProvider: %v", err)
	}
	if !strings.Contains(err.Error(), "calls itself") {
		t.Errorf("the message should name both issuers: %v", err)
	}
}

func TestDiscoveryRefusesIncompleteDocument(t *testing.T) {
	idp := newFakeIdP(t)
	idp.omitTokenURL = true
	p := idp.provider(t)

	_, err := p.Metadata(context.Background())
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("a document with no token endpoint should be refused: %v", err)
	}
}

// The issuer check does not cover an endpoint on another host, so each one is
// checked for https of its own.
func TestDiscoveryRefusesPlainHTTPEndpoint(t *testing.T) {
	idp := newFakeIdP(t)
	idp.authorizeURL = "http://login.example.net/authorize"
	p := idp.provider(t)

	_, err := p.Metadata(context.Background())
	if err == nil || !strings.Contains(err.Error(), "plain-HTTP") {
		t.Fatalf("a plain-HTTP authorization endpoint should be refused: %v", err)
	}
}

func TestDiscoveryOffUsesConfiguredEndpoints(t *testing.T) {
	p := provider(t, config.SSO{
		Discovery:    false,
		AuthorizeURL: "https://idp.example.com/authorize",
		TokenURL:     "https://idp.example.com/token",
		JWKSURL:      "https://idp.example.com/jwks",
	})
	meta, err := p.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.TokenEndpoint != "https://idp.example.com/token" {
		t.Errorf("token endpoint = %q", meta.TokenEndpoint)
	}
}

func TestNewFlowValuesAreDistinctAndLongEnough(t *testing.T) {
	flow, err := NewFlow("/dashboard")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	if flow.Return != "/dashboard" {
		t.Errorf("return = %q", flow.Return)
	}
	if flow.Issued.IsZero() {
		t.Error("a flow with no issue time cannot be expired")
	}
	// RFC 7636 wants 43 to 128 characters for the verifier.
	if len(flow.Verifier) < 43 {
		t.Errorf("verifier is %d characters, RFC 7636 wants at least 43", len(flow.Verifier))
	}
	if flow.State == flow.Nonce || flow.State == flow.Verifier || flow.Nonce == flow.Verifier {
		t.Error("state, nonce and verifier must be three independent values")
	}

	other, err := NewFlow("/dashboard")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	if other.State == flow.State {
		t.Error("two flows got the same state")
	}
}

func TestAuthURLCarriesPKCEStateAndNonce(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.provider(t, func(c *config.SSO) { c.Scopes = []string{"openid", "profile", "email", "groups"} })
	flow, err := NewFlow("/")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}

	raw, err := p.AuthURL(context.Background(), flow, "https://secrets.acme.com/auth/sso/callback")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()

	challenge := sha256.Sum256([]byte(flow.Verifier))
	want := map[string]string{
		"response_type":         "code",
		"client_id":             testClientID,
		"redirect_uri":          "https://secrets.acme.com/auth/sso/callback",
		"state":                 flow.State,
		"nonce":                 flow.Nonce,
		"code_challenge":        b64.EncodeToString(challenge[:]),
		"code_challenge_method": "S256",
		"scope":                 "openid profile email groups",
	}
	for key, value := range want {
		if got := q.Get(key); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
	// The verifier itself must never be in the authorization request: that is
	// the whole point of sending only its hash.
	if strings.Contains(raw, flow.Verifier) {
		t.Error("the PKCE verifier leaked into the authorization URL")
	}
}

func TestAuthURLAppendsToAnEndpointThatAlreadyHasAQuery(t *testing.T) {
	idp := newFakeIdP(t)
	idp.authorizeURL = "https://login.example.net/authorize?p=B2C_1_signin"
	p := idp.provider(t)
	flow, _ := NewFlow("/")

	raw, err := p.AuthURL(context.Background(), flow, "https://secrets.acme.com/auth/sso/callback")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	if strings.Count(raw, "?") != 1 {
		t.Errorf("a second question mark would break the policy parameter: %s", raw)
	}
	if u, err := url.Parse(raw); err != nil || u.Query().Get("p") != "B2C_1_signin" {
		t.Errorf("the endpoint's own parameters were lost: %s", raw)
	}
}

func TestExchangeSendsTheCodeAndVerifiesTheAssertion(t *testing.T) {
	idp := newFakeIdP(t)
	idp.idToken = func(t *testing.T, idp *fakeIdP) string { return idp.sign(t, idp.claims()) }
	p := idp.provider(t)

	flow, _ := NewFlow("/")
	set := idp.claims()
	set["nonce"] = flow.Nonce
	idp.idToken = func(t *testing.T, idp *fakeIdP) string { return idp.sign(t, set) }

	got, err := p.Exchange(context.Background(), "the-code", flow, "https://secrets.acme.com/auth/sso/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got.Subject != "7a1f0e8c-sub" || got.Email != "ops@example.com" {
		t.Errorf("claims = %+v", got)
	}

	form := idp.lastTokenForm
	for key, value := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "the-code",
		"code_verifier": flow.Verifier,
		"client_id":     testClientID,
		"client_secret": "s3cret",
		"redirect_uri":  "https://secrets.acme.com/auth/sso/callback",
	} {
		if got := form.Get(key); got != value {
			t.Errorf("token request %s = %q, want %q", key, got, value)
		}
	}
	if idp.hits.jwks.Load() != 1 {
		t.Errorf("the key set was read %d times for one exchange", idp.hits.jwks.Load())
	}
}

// The nonce is what ties the assertion to the browser that started the flow.
func TestExchangeRefusesATokenForAnotherAttempt(t *testing.T) {
	idp := newFakeIdP(t)
	set := idp.claims()
	set["nonce"] = "the nonce of some other sign-in"
	idp.idToken = func(t *testing.T, idp *fakeIdP) string { return idp.sign(t, set) }
	p := idp.provider(t)

	flow, _ := NewFlow("/")
	_, err := p.Exchange(context.Background(), "the-code", flow, "https://secrets.acme.com/auth/sso/callback")
	if err == nil {
		t.Fatal("an assertion carrying another attempt's nonce was accepted")
	}
	if !errors.Is(err, ErrToken) {
		t.Errorf("error does not wrap ErrToken: %v", err)
	}
}

func TestExchangeRefusesProviderErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"oauth-error", http.StatusBadRequest,
			`{"error":"invalid_grant","error_description":"code expired"}`, "invalid_grant"},
		{"not-json", http.StatusBadGateway, `<html>gateway timeout</html>`, "not JSON"},
		{"no-id-token", http.StatusOK, `{"access_token":"at"}`, "no id_token"},
		{"unexpected-status", http.StatusTeapot, `{"access_token":"at","id_token":"x.y.z"}`, "answered 418"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.tokenStatus, idp.tokenBody = tc.status, tc.body
			p := idp.provider(t)

			flow, _ := NewFlow("/")
			_, err := p.Exchange(context.Background(), "the-code", flow, "https://secrets.acme.com/auth/sso/callback")
			if err == nil {
				t.Fatal("the exchange succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q should contain %q", err, tc.want)
			}
		})
	}
}

func TestCheckKeysCountsThePublishedKeys(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.provider(t)

	n, err := p.CheckKeys(context.Background())
	if err != nil {
		t.Fatalf("CheckKeys: %v", err)
	}
	if n != 1 {
		t.Errorf("CheckKeys = %d, want 1", n)
	}
}

// A stream of tokens naming keys that do not exist must not become a stream of
// requests to the provider.
func TestUnknownKidRefetchesOnceAndThenStops(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.provider(t)
	// Prime the cache.
	if _, err := p.CheckKeys(context.Background()); err != nil {
		t.Fatalf("CheckKeys: %v", err)
	}
	if idp.hits.jwks.Load() != 1 {
		t.Fatalf("jwks hits = %d after priming", idp.hits.jwks.Load())
	}

	forged := signRS256(t, idp.key, "a-kid-that-does-not-exist", idp.claims())
	for i := range 5 {
		if _, err := p.Verify(context.Background(), forged, testNonce); err == nil {
			t.Fatalf("attempt %d: a token naming an unpublished key was accepted", i)
		}
	}
	if got := idp.hits.jwks.Load(); got != 1 {
		t.Errorf("five forged tokens caused %d key-set reads; the refetch is rate-limited to one per %s",
			got, jwksMinInterval)
	}
}

// A rotated key must be picked up without a restart: the cache is a cache, not
// a decision.
func TestRotatedKeyIsPickedUpAfterTheWindow(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.provider(t)
	if _, err := p.CheckKeys(context.Background()); err != nil {
		t.Fatalf("CheckKeys: %v", err)
	}

	// The provider rotates, and the rate-limit window has passed.
	idp.kid = "idp-2"
	p.mu.Lock()
	p.keysFetched = time.Now().Add(-2 * jwksMinInterval)
	p.mu.Unlock()

	set := idp.claims()
	if _, err := p.Verify(context.Background(), signRS256(t, idp.key, "idp-2", set), testNonce); err != nil {
		t.Fatalf("a token signed with the rotated key was refused: %v", err)
	}
	if idp.hits.jwks.Load() != 2 {
		t.Errorf("jwks hits = %d, the rotation should have caused exactly one refetch", idp.hits.jwks.Load())
	}
}

func TestEnabledAndLabel(t *testing.T) {
	var none *Provider
	if none.Enabled() {
		t.Error("a nil provider is not enabled")
	}
	off, err := New(config.SSO{Enabled: false}, discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if off != nil {
		t.Error("a disabled provider should be nil, so every call site has one thing to check")
	}
	on := provider(t, config.SSO{Provider: "entra"})
	if !on.Enabled() {
		t.Error("an enabled provider reports disabled")
	}
	if on.Label() == "" {
		t.Error("the sign-in button has no label")
	}
}
