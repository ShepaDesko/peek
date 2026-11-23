// Package oidc speaks OpenID Connect to one identity provider: discovery, the
// authorization code flow with PKCE, and ID token verification.
//
// It is about six hundred lines and has no dependencies beyond the standard
// library. That is deliberate. The protocol Peek needs is small — one flow,
// one provider, no dynamic registration, no implicit or hybrid response types,
// no token introspection — and the libraries that cover all of it are large
// and configurable, which is the property that gets JWT verification wrong.
// Everything unsafe here is simply absent: there is no code path that accepts
// an unsigned token, a symmetric signature, a response type other than `code`,
// or an issuer other than the configured one.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
)

// Leeway absorbs the clock difference between Peek and the provider. Five
// minutes is what every implementation uses; more would widen the window in
// which an expired assertion is still accepted.
const Leeway = 5 * time.Minute

// jwksTTL is how long a key set is trusted without being re-read. A rotation
// is also picked up immediately through the unknown-kid path below.
const jwksTTL = 15 * time.Minute

// jwksMinInterval rate-limits the unknown-kid refetch, so a stream of tokens
// signed with a bogus kid cannot be turned into a flood against the provider.
const jwksMinInterval = time.Minute

// discoveryTTL caches the discovery document. Endpoints move about as often as
// the issuer does, which is never, but a long-lived process should still pick
// up a migration without a restart.
const discoveryTTL = time.Hour

// httpTimeout bounds every call to the provider. A provider that hangs must
// not hold a sign-in open for ever.
const httpTimeout = 15 * time.Second

// Errors a caller distinguishes.
var (
	// ErrProvider means the identity provider could not be reached or
	// answered something unusable. It is the operator's problem, not the
	// user's, and the message says so.
	ErrProvider = errors.New("oidc: the identity provider")
	// ErrToken means the assertion itself did not check out: a bad
	// signature, the wrong audience, an expired token, a replayed nonce.
	ErrToken = errors.New("oidc: the identity token")
)

// Metadata is the part of the discovery document Peek uses.
type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	ResponseTypes         []string `json:"response_types_supported"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// Claims is what Peek takes from a verified assertion.
type Claims struct {
	Subject string
	Issuer  string
	// Email and Name are what the account is built from. A provider that
	// sends neither is refused: an account with no address cannot be managed.
	Email         string
	EmailVerified bool
	// EmailVerifiedPresent distinguishes "the provider said false" from "the
	// provider did not say": Entra, for one, omits the claim entirely.
	EmailVerifiedPresent bool
	Name                 string
	Groups               []string
	// Raw is the whole claim set, for the one or two providers that need a
	// non-standard field read at the call site.
	Raw map[string]json.RawMessage
}

// Provider talks to one identity provider.
type Provider struct {
	cfg    config.SSO
	log    *slog.Logger
	client *http.Client

	mu          sync.Mutex
	meta        *Metadata
	metaFetched time.Time
	keys        []jsonWebKey
	keysFetched time.Time
}

// New builds a provider from the configuration. It makes no network call: an
// identity provider that is down at boot must not stop Peek from starting,
// because the local administrator account is how you fix it.
func New(cfg config.SSO, log *slog.Logger) (*Provider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // an operator-supplied path
		if err != nil {
			return nil, fmt.Errorf("sso.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("sso.ca_file %s contains no certificate", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("oidc: the default HTTP transport has been replaced; cannot clone it")
	}
	transport := base.Clone()
	transport.TLSClientConfig = tlsCfg

	return &Provider{
		cfg: cfg,
		log: log,
		client: &http.Client{
			Timeout:   httpTimeout,
			Transport: transport,
			// The token endpoint is a destination. A redirect there would be
			// a credential (the client secret) sent somewhere unconfigured.
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) > 0 {
					return errors.New("the identity provider redirected a back-channel call")
				}
				return nil
			},
		},
	}, nil
}

// Enabled reports whether single sign-on is configured.
func (p *Provider) Enabled() bool { return p != nil && p.cfg.Enabled }

// Config exposes the configuration, for the handlers and the sign-in page.
func (p *Provider) Config() config.SSO {
	if p == nil {
		return config.SSO{}
	}
	return p.cfg
}

// Label returns what the sign-in button says.
func (p *Provider) Label() string { return p.Config().Label() }

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// Metadata returns the provider's endpoints, discovered and cached, or built
// from the configuration when discovery is off.
func (p *Provider) Metadata(ctx context.Context) (*Metadata, error) {
	if !p.cfg.Discovery {
		return &Metadata{
			Issuer:                p.cfg.Issuer,
			AuthorizationEndpoint: p.cfg.AuthorizeURL,
			TokenEndpoint:         p.cfg.TokenURL,
			JWKSURI:               p.cfg.JWKSURL,
			UserinfoEndpoint:      p.cfg.UserinfoURL,
		}, nil
	}

	p.mu.Lock()
	if p.meta != nil && time.Since(p.metaFetched) < discoveryTTL {
		meta := p.meta
		p.mu.Unlock()
		return meta, nil
	}
	p.mu.Unlock()

	endpoint := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	var meta Metadata
	if err := p.getJSON(ctx, endpoint, &meta); err != nil {
		return nil, fmt.Errorf("%w could not be discovered at %s: %w", ErrProvider, endpoint, err)
	}
	// The discovery document names its own issuer, and it must be the one we
	// were configured with. Without this check, a provider that serves
	// somebody else's document redirects the whole flow.
	if meta.Issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("%w at %s calls itself %q, but sso.issuer says %q",
			ErrProvider, endpoint, meta.Issuer, p.cfg.Issuer)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return nil, fmt.Errorf("%w published an incomplete discovery document at %s", ErrProvider, endpoint)
	}
	// Everything the flow sends a secret or a code to must be https. The
	// issuer check above does not cover an endpoint on another host.
	for name, raw := range map[string]string{
		"authorization_endpoint": meta.AuthorizationEndpoint,
		"token_endpoint":         meta.TokenEndpoint,
		"jwks_uri":               meta.JWKSURI,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("%w published an unusable %s (%q)", ErrProvider, name, raw)
		}
		if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			return nil, fmt.Errorf("%w published a plain-HTTP %s (%q)", ErrProvider, name, raw)
		}
	}

	p.mu.Lock()
	p.meta, p.metaFetched = &meta, time.Now()
	p.mu.Unlock()
	return &meta, nil
}

// ---------------------------------------------------------------------------
// The authorization request
// ---------------------------------------------------------------------------

// Flow holds the one-time values of a sign-in attempt. The handler keeps them
// in a sealed cookie and hands them back at the callback.
type Flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	// Return is where to send the browser afterwards. Only a path, never a
	// URL: see the handler.
	Return string `json:"r"`
	// Issued is when the flow started, so a stale cookie is refused.
	Issued time.Time `json:"t"`
}

// NewFlow generates the one-time values.
func NewFlow(returnTo string) (Flow, error) {
	state, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	// RFC 7636 allows 43 to 128 characters; 43 is what 32 random bytes give.
	verifier, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	return Flow{State: state, Nonce: nonce, Verifier: verifier, Return: returnTo, Issued: time.Now()}, nil
}

// AuthURL builds the URL to send the browser to.
func (p *Provider) AuthURL(ctx context.Context, flow Flow, redirectURI string) (string, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return "", err
	}
	challenge := sha256.Sum256([]byte(flow.Verifier))

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(p.cfg.ScopeList(), " "))
	q.Set("state", flow.State)
	q.Set("nonce", flow.Nonce)
	// PKCE on a confidential client is belt and braces, and it is what stops
	// an authorization code that leaks through a referrer, a proxy log or a
	// browser extension from being usable by anyone but us.
	q.Set("code_challenge", b64.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return meta.AuthorizationEndpoint + sep + q.Encode(), nil
}

// ---------------------------------------------------------------------------
// The token exchange
// ---------------------------------------------------------------------------

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Exchange trades the authorization code for tokens and verifies the
// assertion. It returns the claims, which is all Peek keeps: the access token
// is used once for userinfo if it is needed, and never stored.
func (p *Provider) Exchange(ctx context.Context, code string, flow Flow, redirectURI string) (*Claims, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", flow.Verifier)
	// client_secret_post rather than basic: Entra, Google and Keycloak all
	// accept it, and ADFS has historically mishandled the Basic variant's
	// form-encoding rules.
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w token endpoint could not be reached: %s", ErrProvider, transportReason(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w token endpoint answer could not be read: %w", ErrProvider, err)
	}

	var tokens tokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("%w token endpoint answered %d with something that is not JSON",
			ErrProvider, resp.StatusCode)
	}
	if tokens.Error != "" {
		// The description comes from the provider and goes in the log, not to
		// the browser: it can name the tenant, the application and the user.
		return nil, fmt.Errorf("%w refused the code: %s (%s)",
			ErrProvider, tokens.Error, tokens.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w token endpoint answered %d", ErrProvider, resp.StatusCode)
	}
	if tokens.IDToken == "" {
		return nil, fmt.Errorf("%w returned no id_token: is the openid scope granted to this application?", ErrProvider)
	}

	claims, err := p.Verify(ctx, tokens.IDToken, flow.Nonce)
	if err != nil {
		return nil, err
	}
	// Fill in what the assertion left out, if the provider offers it. Entra
	// omits the e-mail claim unless the optional claim is configured, and
	// userinfo has it.
	if claims.Email == "" && tokens.AccessToken != "" && meta.UserinfoEndpoint != "" {
		p.fillFromUserinfo(ctx, meta.UserinfoEndpoint, tokens.AccessToken, claims)
	}
	return claims, nil
}

// Verify checks an ID token completely and returns its claims.
func (p *Provider) Verify(ctx context.Context, raw, nonce string) (*Claims, error) {
	header, claims, signed, signature, err := splitJWT(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrToken, err)
	}
	if header.Alg == "" {
		return nil, fmt.Errorf("%w names no algorithm", ErrToken)
	}

	key, err := p.keyFor(ctx, header.Kid, header.Alg)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(header.Alg, key, signed, signature); err != nil {
		return nil, fmt.Errorf("%w signature does not verify (%s): %w", ErrToken, header.Alg, err)
	}

	// Issuer. Exact string comparison, per the specification: a prefix or
	// suffix match is how multi-tenant providers get confused for each other.
	if issuer := stringClaim(claims, "iss"); issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("%w was issued by %q, not %q", ErrToken, issuer, p.cfg.Issuer)
	}
	// Audience. Must contain our client id; when it contains more than that,
	// azp must be us.
	audience := stringOrSlice(claims["aud"])
	if !containsConstantTime(audience, p.cfg.ClientID) {
		return nil, fmt.Errorf("%w is for another application (aud %v)", ErrToken, audience)
	}
	if len(audience) > 1 {
		if azp := stringClaim(claims, "azp"); azp != "" && azp != p.cfg.ClientID {
			return nil, fmt.Errorf("%w was authorised for %q, not for this application", ErrToken, azp)
		}
	}
	now := time.Now()
	exp, ok := numberClaim(claims, "exp")
	if !ok {
		return nil, fmt.Errorf("%w has no expiry", ErrToken)
	}
	if now.After(time.Unix(exp, 0).Add(Leeway)) {
		return nil, fmt.Errorf("%w expired at %s", ErrToken, time.Unix(exp, 0).UTC().Format(time.RFC3339))
	}
	if iat, ok := numberClaim(claims, "iat"); ok {
		if now.Add(Leeway).Before(time.Unix(iat, 0)) {
			return nil, fmt.Errorf("%w was issued in the future (%s); check the clock on this host",
				ErrToken, time.Unix(iat, 0).UTC().Format(time.RFC3339))
		}
	}
	if nbf, ok := numberClaim(claims, "nbf"); ok {
		if now.Add(Leeway).Before(time.Unix(nbf, 0)) {
			return nil, fmt.Errorf("%w is not valid yet", ErrToken)
		}
	}
	// Nonce. This is what ties the assertion to the browser that started the
	// flow: without it a token captured elsewhere could be injected here.
	if nonce != "" {
		got := stringClaim(claims, "nonce")
		if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
			return nil, fmt.Errorf("%w does not carry the nonce of this sign-in attempt", ErrToken)
		}
	}
	subject := stringClaim(claims, "sub")
	if subject == "" {
		return nil, fmt.Errorf("%w has no subject", ErrToken)
	}

	verified, present := boolClaim(claims, "email_verified")
	out := &Claims{
		Subject:              subject,
		Issuer:               p.cfg.Issuer,
		Email:                strings.TrimSpace(stringClaim(claims, "email")),
		EmailVerified:        verified,
		EmailVerifiedPresent: present,
		Name:                 displayName(claims),
		Raw:                  claims,
	}
	if out.Email == "" {
		// Entra puts the address in preferred_username for a work account.
		if candidate := stringClaim(claims, "preferred_username"); strings.Contains(candidate, "@") {
			out.Email = strings.TrimSpace(candidate)
		}
	}
	groups, err := p.groupsFrom(claims)
	if err != nil {
		return nil, err
	}
	out.Groups = groups
	return out, nil
}

// groupsFrom reads the configured group claim.
func (p *Provider) groupsFrom(claims rawClaims) ([]string, error) {
	// Entra replaces the groups claim with a pointer to Microsoft Graph when
	// the user is in more than about two hundred groups. Peek will not call
	// Graph — that is a second outbound dependency and a second credential —
	// so it says what to do instead rather than silently seeing no groups and
	// handing out the default role.
	if _, overflow := claims["_claim_names"]; overflow && p.cfg.MapsGroups() {
		return nil, fmt.Errorf("%w came with a group overflow claim instead of the group list: "+
			"this user is in too many groups for a token. Map application roles instead "+
			"(sso.groups_claim = \"roles\") or assign a group filter in the application registration",
			ErrToken)
	}
	return stringOrSlice(claims[p.cfg.Claim()]), nil
}

func displayName(claims rawClaims) string {
	for _, field := range []string{"name", "given_name", "preferred_username"} {
		if value := strings.TrimSpace(stringClaim(claims, field)); value != "" {
			return value
		}
	}
	return ""
}

// fillFromUserinfo asks the userinfo endpoint for what the assertion lacked.
// A failure is logged and ignored: the assertion is already valid, and the
// caller refuses the sign-in itself if the address is still missing.
func (p *Provider) fillFromUserinfo(ctx context.Context, endpoint, accessToken string, out *Claims) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Warn("userinfo could not be read", "error", transportReason(err))
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		p.log.Warn("userinfo answered unexpectedly", "status", resp.StatusCode)
		return
	}
	var claims rawClaims
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return
	}
	// The subject must match: userinfo for somebody else is not an answer.
	if subject := stringClaim(claims, "sub"); subject != out.Subject {
		p.log.Warn("userinfo described a different subject than the token; ignoring it")
		return
	}
	if out.Email == "" {
		out.Email = strings.TrimSpace(stringClaim(claims, "email"))
		if verified, present := boolClaim(claims, "email_verified"); present {
			out.EmailVerified, out.EmailVerifiedPresent = verified, true
		}
	}
	if out.Name == "" {
		out.Name = displayName(claims)
	}
	if len(out.Groups) == 0 {
		out.Groups = stringOrSlice(claims[p.cfg.Claim()])
	}
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

// keyFor resolves the signing key for a token header.
//
// A cached set is used when it is fresh. An unknown kid triggers one refetch,
// rate-limited, which is how a key rotation is picked up without waiting for
// the cache to expire — and without letting a stream of bogus kids turn into a
// flood against the provider.
func (p *Provider) keyFor(ctx context.Context, kid, alg string) (any, error) {
	if strings.HasPrefix(alg, "HS") || alg == "none" {
		// Not supported, and the message says why rather than "unsupported".
		return nil, fmt.Errorf("%w is signed with %s. Peek verifies asymmetric signatures only: "+
			"configure your provider to sign with RS256 or ES256", ErrToken, alg)
	}

	keys, fresh := p.cachedKeys()
	if key := pickKey(keys, kid, alg); key != nil {
		return key.public()
	}
	if fresh && kid != "" && !p.mayRefetch() {
		return nil, fmt.Errorf("%w names a signing key (%q) this provider has not published", ErrToken, kid)
	}

	if err := p.fetchKeys(ctx); err != nil {
		return nil, err
	}
	keys, _ = p.cachedKeys()
	key := pickKey(keys, kid, alg)
	if key == nil {
		return nil, fmt.Errorf("%w names a signing key (%q) the provider does not publish", ErrToken, kid)
	}
	pub, err := key.public()
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, fmt.Errorf("%w is signed with a key type Peek does not accept (%s)", ErrToken, key.Kty)
	}
	return pub, nil
}

// CheckKeys reads the key set and reports how many usable signing keys the
// provider publishes. peek doctor calls it: a key set that cannot be read is a
// sign-in that fails at the last step, with nothing in the browser to explain
// it.
func (p *Provider) CheckKeys(ctx context.Context) (int, error) {
	if err := p.fetchKeys(ctx); err != nil {
		return 0, err
	}
	keys, _ := p.cachedKeys()
	usable := 0
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		pub, err := key.public()
		if err != nil || pub == nil {
			continue
		}
		usable++
	}
	if usable == 0 {
		return 0, fmt.Errorf("%w publishes %d key(s), none of them a usable signing key",
			ErrProvider, len(keys))
	}
	return usable, nil
}

func (p *Provider) cachedKeys() ([]jsonWebKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keys, time.Since(p.keysFetched) < jwksTTL
}

func (p *Provider) mayRefetch() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Since(p.keysFetched) >= jwksMinInterval
}

func (p *Provider) fetchKeys(ctx context.Context) error {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return err
	}
	var set keySet
	if err := p.getJSON(ctx, meta.JWKSURI, &set); err != nil {
		return fmt.Errorf("%w key set could not be read from %s: %w", ErrProvider, meta.JWKSURI, err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("%w published an empty key set at %s", ErrProvider, meta.JWKSURI)
	}
	p.mu.Lock()
	p.keys, p.keysFetched = set.Keys, time.Now()
	p.mu.Unlock()
	return nil
}

// pickKey finds the key a token header names.
//
// With no kid — some providers publish a single key and omit it — the only
// candidate is used, and an ambiguous set is refused rather than guessed at:
// trying each key in turn is how a verifier ends up accepting a signature from
// a key that was never meant for tokens.
func pickKey(keys []jsonWebKey, kid, alg string) *jsonWebKey {
	var candidates []jsonWebKey
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Alg != "" && key.Alg != alg {
			continue
		}
		if kid != "" {
			if key.Kid == kid {
				return &key //nolint:gosec,exportloopref // Go 1.22+: the loop variable is per-iteration
			}
			continue
		}
		candidates = append(candidates, key)
	}
	if kid == "" && len(candidates) == 1 {
		return &candidates[0]
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (p *Provider) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.New(transportReason(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// A megabyte is far more than any discovery document or key set, and it
	// stops a hostile or broken provider from exhausting memory here.
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64.EncodeToString(buf), nil
}

// containsConstantTime avoids leaking, through timing, which audience values
// were close to ours. The list is tiny, so the cost is nothing.
func containsConstantTime(list []string, want string) bool {
	found := 0
	for _, value := range list {
		found |= subtle.ConstantTimeCompare([]byte(value), []byte(want))
	}
	return found == 1
}

// transportReason strips the URL out of a net/http error. A token endpoint URL
// is not a secret, but a userinfo or discovery URL can carry a tenant
// identifier, and the rule in this project is that nothing of the sort reaches
// a log by accident.
func transportReason(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}
