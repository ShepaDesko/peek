package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/auth"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// Session cookies and the middleware that turns them into a principal.

const (
	sessionCookie = "peek_session"
	csrfCookie    = "peek_csrf"
	csrfHeader    = "X-Peek-CSRF"
)

type principalKey struct{}

// principalOf returns the authenticated caller, or nil.
func principalOf(ctx context.Context) *accounts.Principal {
	p, _ := ctx.Value(principalKey{}).(*accounts.Principal)
	return p
}

// setSessionCookies writes both cookies after a successful sign-in.
//
// The session cookie is HttpOnly so script cannot read it; the CSRF cookie is
// deliberately readable, because the interface has to echo it back in a
// header — that echo is what proves the request came from our own page.
func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, token, csrf string, expires time.Time) {
	secure := s.cfg.HTTPS() || s.trusted.Scheme(r) == "https"
	//nolint:gosec // G124: Secure is set from the deployment (HTTPS or a trusted proxy), HttpOnly and SameSite are set below
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	if csrf != "" {
		// Readable by script on purpose: the interface echoes it in a header.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: see above
			Name:     csrfCookie,
			Value:    csrf,
			Path:     "/",
			Expires:  expires,
			HttpOnly: false,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func (s *Server) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := s.cfg.HTTPS() || s.trusted.Scheme(r) == "https"
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: an expiring cookie with no value
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == sessionCookie,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// bearerToken returns the API token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// withPrincipal attaches the caller, from a session cookie or an API token.
// It never rejects: routes decide for themselves whether they need one.
//
// The cookie wins when both are present. A browser that is signed in and also
// sends a token is an odd thing, and picking the cookie means the interface
// never behaves differently because something left a header behind.
func (s *Server) withPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.accounts == nil {
			next.ServeHTTP(w, r)
			return
		}
		if token := sessionToken(r); token != "" {
			p, err := s.accounts.Authenticate(r.Context(), token)
			if err == nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
				return
			}
			if errors.Is(err, accounts.ErrAccountDisabled) {
				s.clearSessionCookies(w, r)
			}
			next.ServeHTTP(w, r)
			return
		}
		raw := bearerToken(r)
		if raw == "" {
			next.ServeHTTP(w, r)
			return
		}
		p, err := s.accounts.AuthenticateToken(r.Context(), raw)
		if err != nil {
			// A bad token is told so, unlike a bad cookie: a script has no
			// sign-in page to be redirected to, and silently acting as an
			// anonymous caller would produce a confusing 401 further down.
			writeError(w, r, http.StatusUnauthorized, "bad_api_token",
				"This API token is unknown, revoked or expired.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// requireScope refuses a token caller that does not carry one of these scopes.
// A session caller passes: a signed-in person is bounded by their role, which
// requireRole checks separately.
func (s *Server) requireScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := principalOf(r.Context())
			if p == nil || p.HasScope(scopes...) {
				next.ServeHTTP(w, r)
				return
			}
			s.audit(r, store.AuditEvent{
				OrgID:  p.User.OrgID,
				UserID: p.User.ID,
				Event:  store.EventTokenBlocked,
				Detail: map[string]string{
					"token":    p.Token.Name,
					"required": strings.Join(scopes, "|"),
					"scopes":   strings.Join(p.Token.Scopes, " "),
				},
			})
			writeError(w, r, http.StatusForbidden, "missing_scope",
				"This API token does not carry the scope this call needs: "+strings.Join(scopes, " or ")+".")
		})
	}
}

// requireAuth refuses anonymous callers.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principalOf(r.Context()) == nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireRole refuses callers below a role. The auditor role is accepted only
// where it is listed explicitly, because it sits outside the ladder.
func (s *Server) requireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := principalOf(r.Context())
			if p == nil {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
				return
			}
			for _, role := range roles {
				if p.User.Role == role || (role != store.RoleAuditor && p.User.Can(role)) {
					next.ServeHTTP(w, r)
					return
				}
			}
			s.audit(r, store.AuditEvent{
				UserID: p.User.ID,
				Event:  store.EventAdminBlocked,
				Detail: map[string]string{"required": strings.Join(roles, "|"), "role": p.User.Role},
			})
			writeError(w, r, http.StatusForbidden, "forbidden", "Your role does not allow this.")
		})
	}
}

// requireCSRF enforces the double-submit token on state-changing requests
// made with a session cookie.
//
// SameSite=Lax already blocks most cross-site POSTs, but it is a browser
// default rather than a guarantee, and it does nothing for a browser that
// ignores it. The header has to be set by script on our own origin, which the
// attacker's page cannot do.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		p := principalOf(r.Context())
		if p == nil || p.IsToken() {
			// No session: there is no cookie to ride on. A bearer token is the
			// same case — an attacker's page cannot make the browser attach a
			// header it does not know.
			next.ServeHTTP(w, r)
			return
		}
		if !s.accounts.CheckCSRF(p, r.Header.Get(csrfHeader)) {
			writeError(w, r, http.StatusForbidden, "csrf", "Missing or invalid CSRF token. Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	res, err := s.accounts.Login(r.Context(), s.orgOf(r), req.Email, req.Password,
		ClientIP(r.Context()), r.UserAgent())
	if err != nil {
		s.auditLogin(r, req.Email, err)
		switch {
		case errors.Is(err, accounts.ErrAccountLocked):
			writeError(w, r, http.StatusTooManyRequests, "locked",
				"Too many failed attempts. Try again in a few minutes.")
		case errors.Is(err, accounts.ErrAccountDisabled):
			writeError(w, r, http.StatusForbidden, "disabled", "This account is disabled.")
		case errors.Is(err, accounts.ErrInvalidCredentials):
			// One answer for a wrong address and a wrong password.
			writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Wrong e-mail address or password.")
		default:
			s.log.Error("login", "error", err.Error())
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}

	s.setSessionCookies(w, r, res.SessionToken, res.CSRFToken, res.ExpiresAt)
	s.audit(r, store.AuditEvent{
		UserID: res.User.ID,
		Event:  store.EventLogin,
		Detail: map[string]string{"mfa_required": boolString(res.MFARequired)},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"mfa_required":    res.MFARequired,
		"must_enrol_totp": res.MustEnrolTOTP,
		"user":            publicUser(res.User),
		"csrf_token":      res.CSRFToken,
	})
}

func (s *Server) auditLogin(r *http.Request, email string, err error) {
	reason := "invalid_credentials"
	switch {
	case errors.Is(err, accounts.ErrAccountLocked):
		reason = "locked"
	case errors.Is(err, accounts.ErrAccountDisabled):
		reason = "disabled"
	}
	// The address is recorded because an administrator needs to see which
	// account is being attacked; the password never is.
	s.audit(r, store.AuditEvent{
		Event:  store.EventLoginFailed,
		Detail: map[string]string{"email": store.NormalizeEmail(email), "reason": reason},
	})
}

type mfaRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	token := sessionToken(r)
	res, err := s.accounts.CompleteMFA(r.Context(), token, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoSession):
			writeError(w, r, http.StatusUnauthorized, "no_session", "This sign-in attempt expired. Start again.")
		case errors.Is(err, accounts.ErrAccountLocked):
			writeError(w, r, http.StatusTooManyRequests, "locked", "Too many failed attempts.")
		default:
			s.audit(r, store.AuditEvent{Event: store.EventMFAFailed})
			writeError(w, r, http.StatusUnauthorized, "bad_code", "Wrong code.")
		}
		return
	}
	s.setSessionCookies(w, r, token, "", res.ExpiresAt)
	s.audit(r, store.AuditEvent{UserID: res.User.ID, Event: store.EventLogin,
		Detail: map[string]string{"second_factor": "totp"}})
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(res.User)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if p := principalOf(r.Context()); p != nil {
		s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventLogout})
	}
	if err := s.accounts.Logout(r.Context(), sessionToken(r)); err != nil {
		s.log.Error("logout", "error", err.Error())
	}
	s.clearSessionCookies(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// handleMe describes the caller and what the interface may offer them.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil {
		// Not signed in: say what sign-in methods exist, and whether the
		// instance still needs its first account.
		needsBootstrap := false
		if s.accounts != nil {
			if empty, err := s.accounts.NeedsBootstrap(r.Context(), s.orgOf(r)); err == nil {
				needsBootstrap = empty
			}
		}
		pending := false
		if token := sessionToken(r); token != "" {
			pending, _ = s.accounts.PendingMFA(r.Context(), token)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":    false,
			"mfa_pending":      pending,
			"needs_bootstrap":  needsBootstrap,
			"passkeys":         s.accounts != nil && s.accounts.PasskeySupported(),
			"anonymous_create": s.cfg.Security.AnonymousCreate,
		})
		return
	}

	recovery, _ := s.accounts.RemainingRecoveryCodes(r.Context(), p.User.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":   true,
		"user":            publicUser(p.User),
		"csrf_token":      r.Header.Get(csrfHeader),
		"has_totp":        p.User.HasTOTP(),
		"recovery_left":   recovery,
		"require_totp":    s.cfg.Security.RequireTOTP,
		"passkeys":        s.accounts.PasskeySupported(),
		"can_manage":      p.User.Can(store.RoleManager),
		"can_administer":  p.User.Can(store.RoleAdmin),
		"can_audit":       p.User.Can(store.RoleManager) || p.User.Role == store.RoleAuditor,
		"session_expires": p.Session.ExpiresAt,
	})
}

type bootstrapRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// handleBootstrap creates the first administrator of a fresh instance.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	var req bootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	user, err := s.accounts.Bootstrap(r.Context(), s.orgOf(r), req.Email, req.Password, req.DisplayName)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: user.ID, Event: store.EventUserCreated,
		Detail: map[string]string{"role": user.Role, "bootstrap": "true"}})

	res, err := s.accounts.Login(r.Context(), s.orgOf(r), req.Email, req.Password, ClientIP(r.Context()), r.UserAgent())
	if err != nil {
		writeJSON(w, http.StatusCreated, map[string]any{"user": publicUser(user)})
		return
	}
	s.setSessionCookies(w, r, res.SessionToken, res.CSRFToken, res.ExpiresAt)
	writeJSON(w, http.StatusCreated, map[string]any{"user": publicUser(user), "csrf_token": res.CSRFToken})
}

type changePasswordRequest struct {
	Current string `json:"current"`
	Next    string `json:"next"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	if err := s.accounts.ChangePassword(r.Context(), p, req.Current, req.Next); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventPasswordChanged})
	w.WriteHeader(http.StatusNoContent)
}

type forgotRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	token, user, err := s.accounts.StartPasswordReset(r.Context(), s.orgOf(r), req.Email)
	if err != nil {
		s.log.Error("start password reset", "error", err.Error())
	}
	if token != "" {
		s.audit(r, store.AuditEvent{UserID: user.ID, Event: store.EventPasswordResetRequested})
		if err := s.mailPasswordReset(r.Context(), user, token); err != nil {
			s.log.Error("send password reset", "error", err.Error())
		}
	}
	// The answer is the same whether or not the address exists.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"sent":            true,
		"mail_configured": s.cfg.Mail.Host != "",
	})
}

type resetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.accounts.CompletePasswordReset(r.Context(), req.Token, req.Password); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{Event: store.EventPasswordReset})
	w.WriteHeader(http.StatusNoContent)
}

// --- second factor -----------------------------------------------------------

func (s *Server) handleTOTPStart(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	enrolment, err := s.accounts.StartTOTP(r.Context(), p, s.brandName())
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": enrolment.Secret, "uri": enrolment.URI})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var req mfaRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	codes, err := s.accounts.ConfirmTOTP(r.Context(), p, req.Code)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventTOTPEnabled})
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

type passwordConfirmRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req passwordConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	if err := s.accounts.DisableTOTP(r.Context(), p, req.Password); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventTOTPDisabled})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	codes, err := s.accounts.RegenerateRecoveryCodes(r.Context(), p)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventRecoveryCodesIssued})
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// --- sessions ----------------------------------------------------------------

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	sessions, err := s.accounts.Sessions(r.Context(), p.User.ID)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, map[string]any{
			"id":           sess.ID,
			"current":      sess.ID == p.Session.ID,
			"created_at":   sess.CreatedAt,
			"last_seen_at": sess.LastSeenAt,
			"expires_at":   sess.ExpiresAt,
			"ip":           s.logIP(sess.IP),
			"user_agent":   sess.UserAgent,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.accounts.RevokeSession(r.Context(), p.User.ID, id); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	if id == p.Session.ID {
		s.clearSessionCookies(w, r)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	n, err := s.accounts.RevokeOtherSessions(r.Context(), p.User.ID, p.Session.ID)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventSessionsRevoked,
		Detail: map[string]string{"count": strconv.FormatInt(n, 10)}})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// --- helpers -----------------------------------------------------------------

// orgOf resolves the organisation a request belongs to. Single-tenant
// instances always answer "default"; multi-org resolution arrives with M9.
func (s *Server) orgOf(_ *http.Request) string { return store.DefaultOrgID }

func (s *Server) brandName() string {
	if s.cfg.Branding.ServiceName != "" {
		return s.cfg.Branding.ServiceName
	}
	return "Peek"
}

// publicUser is what the interface is allowed to see about an account.
func publicUser(u store.User) map[string]any {
	return map[string]any{
		"id":                   u.ID,
		"email":                u.Email,
		"display_name":         u.DisplayName,
		"role":                 u.Role,
		"status":               u.Status,
		"has_totp":             u.HasTOTP(),
		"must_change_password": u.MustChangePassword,
		"created_at":           u.CreatedAt,
		"last_login_at":        nilTime(u.LastLoginAt),
	}
}

// writeAccountError maps the service errors to answers, once, in one place.
func (s *Server) writeAccountError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, accounts.ErrNoSession):
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
	case errors.Is(err, accounts.ErrForbidden), errors.Is(err, accounts.ErrPasskeysDisabled):
		writeError(w, r, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, accounts.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "Not found, or no longer valid.")
	case errors.Is(err, accounts.ErrInvalidCredentials):
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Wrong password.")
	case errors.Is(err, accounts.ErrAccountLocked):
		writeError(w, r, http.StatusTooManyRequests, "locked", "Too many failed attempts.")
	case errors.Is(err, accounts.ErrTOTPNotEnrolled):
		writeError(w, r, http.StatusConflict, "no_totp", "No authenticator is enrolled on this account.")
	case errors.Is(err, store.ErrUserExists):
		writeError(w, r, http.StatusConflict, "exists", "An account already exists for that address.")
	case isWeakPassword(err):
		writeFieldError(w, http.StatusUnprocessableEntity, "weak_password", err.Error(), "password")
	case isBadCode(err):
		writeError(w, r, http.StatusUnauthorized, "bad_code", "Wrong code.")
	case errors.Is(err, pcrypto.ErrNoMasterKey):
		// Enrolling a second factor needs the server master key to encrypt the
		// seed. Say which file is missing instead of a blank 500.
		writeError(w, r, http.StatusServiceUnavailable, "no_master_key",
			"This instance has no master key, so a second factor cannot be stored. Run: sudo peek key rotate --init")
	default:
		s.log.Error("account operation", "route", routePattern(r), "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// isWeakPassword and isBadCode keep the error mapping readable without
// importing the credential package into every handler.
func isWeakPassword(err error) bool { return errors.Is(err, auth.ErrWeakPassword) }

func isBadCode(err error) bool { return errors.Is(err, auth.ErrBadCode) }

// requireSession refuses a bearer-token caller.
//
// It guards everything that changes credentials, users, sessions or the brand.
// A token is for scripts that send and manage secrets; a token that could
// change a password, mint another token or disable an account would turn one
// leaked string into a permanent hold on the instance.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r.Context())
		if p != nil && p.IsToken() {
			writeError(w, r, http.StatusForbidden, "session_required",
				"This call needs a signed-in session, not an API token.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
