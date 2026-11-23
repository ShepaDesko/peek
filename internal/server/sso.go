package server

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/oidc"
	"github.com/ShepaDesko/peek/internal/store"
)

// Single sign-on, as two plain browser routes rather than an API dance.
//
// /auth/sso redirects to the provider and /auth/sso/callback comes back. The
// single-page application is not involved in either, which removes a whole
// category of mistake: no token in a URL the script can read, no fragment to
// parse, no window.postMessage between origins. The callback sets the same
// session cookie a password sign-in would and redirects to the interface.

const (
	// ssoFlowCookie carries the one-time values of an attempt, sealed with
	// the server master key. The state, the nonce and the PKCE verifier are
	// all inside it, so an attempt is bound to the browser that started it
	// and no server-side table has to be swept.
	ssoFlowCookie = "peek_sso"
	// ssoFlowLifetime is how long a sign-in may take. Long enough to type a
	// password and approve a push at the provider; short enough that a
	// forgotten tab is not a usable attempt.
	ssoFlowLifetime = 15 * time.Minute
	// ssoFlowPurpose is the AEAD label: a sealed flow cookie can never be
	// read as anything else.
	ssoFlowPurpose = "sso-flow"
)

// handleSSOInfo tells the sign-in page what to show. Unauthenticated by
// necessity — it is read before anybody has signed in — and it says nothing a
// visitor to the internal listener could not infer from the button itself.
func (s *Server) handleSSOInfo(w http.ResponseWriter, _ *http.Request) {
	sso := s.cfg.SSO
	body := map[string]any{
		"enabled": sso.Enabled && s.sso.Enabled(),
		// Required hides local password sign-in in the interface. Passkeys
		// stay available: an instance whose only way in is a provider that is
		// down is an instance nobody can repair.
		"required": sso.Enabled && sso.Required,
	}
	if sso.Enabled {
		body["label"] = sso.Label()
		body["start_url"] = "/auth/sso"
	}
	writeJSON(w, http.StatusOK, body)
}

// handleSSOStart begins the flow.
func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	if !s.sso.Enabled() {
		writeError(w, r, http.StatusNotFound, "sso_disabled", "Single sign-on is not configured.")
		return
	}
	if s.cipher == nil {
		// The flow cookie is sealed with the master key. Without one, the
		// state and the nonce could be forged, which is the whole protection
		// against a cross-site sign-in. Refuse loudly.
		s.log.Error("single sign-on needs the server master key to seal its state cookie",
			"master_key_file", s.cfg.MasterKeyFile)
		s.redirectToLogin(w, r, "unavailable")
		return
	}

	flow, err := oidc.NewFlow(safeReturnPath(r.URL.Query().Get("return")))
	if err != nil {
		s.log.Error("cannot start a single sign-on attempt", "error", err.Error())
		s.redirectToLogin(w, r, "unavailable")
		return
	}
	sealed, err := s.sealFlow(flow)
	if err != nil {
		s.log.Error("cannot seal the single sign-on state", "error", err.Error())
		s.redirectToLogin(w, r, "unavailable")
		return
	}
	target, err := s.sso.AuthURL(r.Context(), flow, s.cfg.RedirectURI())
	if err != nil {
		// Discovery failed: the operator needs the detail, the visitor does
		// not get it.
		s.log.Error("cannot build the single sign-on redirect", "error", err.Error())
		s.redirectToLogin(w, r, "provider")
		return
	}

	s.setFlowCookie(w, r, sealed)
	w.Header().Set("Cache-Control", "no-store")
	// The destination is the provider's authorization endpoint: either
	// sso.authorize_url from peek.toml, or a discovery document whose own
	// issuer was checked against sso.issuer. Nothing from the request reaches
	// it — the only caller-supplied value, `return`, is reduced to a path by
	// safeReturnPath and goes into the sealed cookie, not here.
	//nolint:gosec // G710: the target comes from the operator's configuration, not from the request
	http.Redirect(w, r, target, http.StatusFound)
}

// handleSSOCallback finishes the flow.
func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	if !s.sso.Enabled() || s.cipher == nil {
		s.redirectToLogin(w, r, "unavailable")
		return
	}
	// Whatever happens next, this attempt is over: the cookie is single use.
	//
	// Cleared here rather than in a defer, because http.Redirect writes the
	// header, and a Set-Cookie added after that is silently dropped. The
	// deferred version looked right and left the cookie in the browser.
	s.clearFlowCookie(w, r)

	q := r.URL.Query()
	if providerError := q.Get("error"); providerError != "" {
		// access_denied is the user pressing cancel, or an administrator
		// having not granted consent. It is not a Peek failure.
		s.log.Info("the identity provider refused the sign-in",
			"error", providerError, "description", q.Get("error_description"))
		if providerError == "access_denied" {
			s.redirectToLogin(w, r, "cancelled")
			return
		}
		s.redirectToLogin(w, r, "provider")
		return
	}

	flow, err := s.openFlow(r)
	if err != nil {
		// No cookie, a tampered one, or one that outlived the attempt. The
		// usual innocent cause is a bookmarked callback URL.
		s.log.Warn("single sign-on callback without a usable attempt", "error", err.Error())
		s.redirectToLogin(w, r, "expired")
		return
	}
	// The state parameter is what ties this callback to the attempt. A
	// mismatch is either a stale tab or a cross-site sign-in attempt.
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		s.audit(r, store.AuditEvent{Event: store.EventSSOFailed,
			Detail: map[string]string{"reason": "state_mismatch"}})
		s.redirectToLogin(w, r, "state")
		return
	}
	code := q.Get("code")
	if code == "" {
		s.redirectToLogin(w, r, "provider")
		return
	}

	claims, err := s.sso.Exchange(r.Context(), code, flow, s.cfg.RedirectURI())
	if err != nil {
		// The detail names the tenant, the application and sometimes the
		// user: it belongs in the log, not in a query string.
		s.log.Error("single sign-on exchange failed", "error", err.Error())
		s.audit(r, store.AuditEvent{Event: store.EventSSOFailed,
			Detail: map[string]string{"reason": exchangeReason(err)}})
		s.redirectToLogin(w, r, exchangeReason(err))
		return
	}

	res, err := s.accounts.SignInWithSSO(r.Context(), claims, ClientIP(r.Context()), r.UserAgent())
	if err != nil {
		s.log.Warn("single sign-on was refused by policy",
			"subject", claims.Subject, "error", err.Error())
		s.audit(r, store.AuditEvent{Event: store.EventSSOFailed,
			Detail: map[string]string{"reason": policyReason(err)}})
		s.redirectToLogin(w, r, policyReason(err))
		return
	}

	// In multi-organisation mode the address decides which organisation this
	// sign-in belongs to, and the account has to belong to it. Without this,
	// an acme account signing in on beta's domain would get a session that
	// every subsequent API call then refuses — a working sign-in followed by
	// a wall, which is the worst way to tell somebody they used the wrong
	// address.
	if s.orgs.MultiOrg() {
		resolved := OrgOf(r.Context()).ID
		if res.User.OrgID != resolved && res.User.Role != store.RolePlatformAdmin {
			s.audit(r, store.AuditEvent{
				Event:  store.EventWrongOrg,
				UserID: res.User.ID,
				Detail: map[string]string{"account_org": res.User.OrgID, "requested_org": resolved},
			})
			s.redirectToLogin(w, r, "wrong_organisation")
			return
		}
	}

	detail := map[string]string{"issuer": claims.Issuer, "role": res.User.Role}
	switch {
	case res.Provisioned:
		detail["account"] = "provisioned"
	case res.Linked:
		detail["account"] = "linked"
	default:
		detail["account"] = "existing"
	}
	if res.RoleChanged != "" {
		detail["role_from_directory"] = res.RoleChanged
	}
	s.audit(r, store.AuditEvent{Event: store.EventSSOLogin, UserID: res.User.ID, Detail: detail})
	if res.Provisioned {
		s.audit(r, store.AuditEvent{Event: store.EventUserCreated, UserID: res.User.ID,
			Detail: map[string]string{"created": res.User.ID, "role": res.User.Role, "by": "sso"}})
	}

	s.setSessionCookies(w, r, res.SessionToken, res.CSRFToken, res.ExpiresAt)
	w.Header().Set("Cache-Control", "no-store")

	target := flow.Return
	if res.MFARequired {
		// The session exists but carries no authority yet: send the browser
		// to the second-factor page rather than to the dashboard.
		target = "/login?mfa=1"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// ---------------------------------------------------------------------------
// The flow cookie
// ---------------------------------------------------------------------------

func (s *Server) sealFlow(flow oidc.Flow) (string, error) {
	buf, err := json.Marshal(flow)
	if err != nil {
		return "", err
	}
	sealed, err := s.cipher.Seal(ssoFlowPurpose, buf)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Server) openFlow(r *http.Request) (oidc.Flow, error) {
	var flow oidc.Flow
	cookie, err := r.Cookie(ssoFlowCookie)
	if err != nil {
		return flow, errors.New("no sign-in attempt cookie")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return flow, errors.New("the attempt cookie is not valid base64url")
	}
	buf, err := s.cipher.Open(ssoFlowPurpose, sealed)
	if err != nil {
		// Either tampering or a master key that has been rotated mid-flow.
		return flow, errors.New("the attempt cookie does not open")
	}
	if err := json.Unmarshal(buf, &flow); err != nil {
		return flow, err
	}
	if flow.State == "" || flow.Nonce == "" || flow.Verifier == "" {
		return flow, errors.New("the attempt cookie is incomplete")
	}
	if time.Since(flow.Issued) > ssoFlowLifetime {
		return flow, errors.New("the attempt took too long")
	}
	// Normalise here too: a cookie is sealed, not trusted. A master key is
	// per-instance, so this is belt and braces, but the redirect below is the
	// one place an open redirect could appear.
	flow.Return = safeReturnPath(flow.Return)
	return flow, nil
}

func (s *Server) setFlowCookie(w http.ResponseWriter, r *http.Request, value string) {
	secure := s.cfg.HTTPS() || s.trusted.Scheme(r) == "https"
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure follows the deployment; HttpOnly and SameSite are set here
		Name:     ssoFlowCookie,
		Value:    value,
		Path:     "/auth/sso",
		Expires:  time.Now().Add(ssoFlowLifetime),
		HttpOnly: true,
		Secure:   secure,
		// Lax, not Strict: the callback arrives as a cross-site navigation
		// from the provider, and Strict would withhold the cookie exactly
		// when it is needed. Lax sends it on a top-level GET, which is what
		// the callback is.
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearFlowCookie(w http.ResponseWriter, r *http.Request) {
	secure := s.cfg.HTTPS() || s.trusted.Scheme(r) == "https"
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: an expiring cookie with no value
		Name:     ssoFlowCookie,
		Value:    "",
		Path:     "/auth/sso",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// safeReturnPath reduces whatever was asked for to a path on this instance.
//
// This is the open-redirect guard, and it is deliberately brutal: anything
// that is not a single-slash-rooted path with no scheme, no host and no
// backslash becomes "/". A sign-in flow that can be made to land on another
// site is a phishing primitive, and the interface only ever needs a path.
func safeReturnPath(raw string) string {
	if raw == "" || raw[0] != '/' {
		return "/"
	}
	// "//evil.example" is a scheme-relative URL, and "/\evil.example" is one
	// too in several browsers.
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	if strings.ContainsAny(raw, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return u.RequestURI()
}

// redirectToLogin sends the browser back to the sign-in page with a code the
// interface turns into a sentence. Codes, not messages: a message in a query
// string is a place to inject text into the page.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(reason), http.StatusFound)
}

// exchangeReason maps an oidc failure to one of the codes the interface knows.
func exchangeReason(err error) string {
	switch {
	case errors.Is(err, oidc.ErrToken):
		return "token"
	case errors.Is(err, oidc.ErrProvider):
		return "provider"
	default:
		return "provider"
	}
}

// policyReason maps an accounts refusal to one of the codes the interface
// knows. Each one gets its own sentence: "sign-in failed" right after a
// successful sign-in at the provider is the most confusing thing a product
// can say.
func policyReason(err error) string {
	switch {
	case errors.Is(err, accounts.ErrSSODomain):
		return "domain"
	case errors.Is(err, accounts.ErrSSONoAccount):
		return "no_account"
	case errors.Is(err, accounts.ErrSSONoGroup):
		return "no_group"
	case errors.Is(err, accounts.ErrSSONoEmail):
		return "no_email"
	case errors.Is(err, accounts.ErrSSOClaimed):
		return "claimed"
	case errors.Is(err, accounts.ErrAccountDisabled):
		return "disabled"
	case errors.Is(err, accounts.ErrAccountLocked):
		return "locked"
	default:
		return "unavailable"
	}
}
