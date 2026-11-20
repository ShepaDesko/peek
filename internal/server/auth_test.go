package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// session is a signed-in caller in the tests: it carries the cookies a browser
// would, and echoes the CSRF token the way the interface does.
type session struct {
	cookies map[string]string
	csrf    string
	user    map[string]any
}

// do issues a request as this session.
func (sess *session) do(t *testing.T, h http.Handler, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.RemoteAddr = "192.0.2.10:54321"
	for name, value := range sess.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if sess.csrf != "" {
		req.Header.Set("X-Peek-CSRF", sess.csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	sess.absorb(rec)
	return rec
}

// absorb keeps the cookie jar up to date, like a browser.
func (sess *session) absorb(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(sess.cookies, c.Name)
			continue
		}
		sess.cookies[c.Name] = c.Value
		if c.Name == "peek_csrf" {
			sess.csrf = c.Value
		}
	}
}

const (
	testAdminEmail    = "admin@acme.example"
	testPassword      = "un-mot-de-passe-correct-2026"
	testOtherPassword = "un-autre-mot-de-passe-2026"
)

// signIn bootstraps the first administrator and returns a signed-in session.
func (h *harness) signIn(t *testing.T) *session {
	t.Helper()
	sess := &session{cookies: map[string]string{}}
	body, err := json.Marshal(map[string]string{
		"email": testAdminEmail, "password": testPassword, "display_name": "Admin ACME",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := sess.do(t, h.internal, http.MethodPost, "/api/v1/auth/bootstrap", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bootstrap: %d %s", rec.Code, rec.Body.String())
	}
	if sess.cookies["peek_session"] == "" || sess.csrf == "" {
		t.Fatalf("bootstrap set no session: %v", sess.cookies)
	}
	sess.user = decodeBody(t, rec)["user"].(map[string]any)
	return sess
}

// signInAs signs an existing account in with a password.
func (h *harness) signInAs(t *testing.T, email, password string) *session {
	t.Helper()
	sess := &session{cookies: map[string]string{}}
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	rec := sess.do(t, h.internal, http.MethodPost, "/api/v1/auth/login", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login as %s: %d %s", email, rec.Code, rec.Body.String())
	}
	return sess
}

func jsonBody(t *testing.T, value any) []byte {
	t.Helper()
	buf, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// TestBootstrapOnceThenNever checks the first-run path cannot be replayed.
func TestBootstrapOnceThenNever(t *testing.T) {
	h := newHarness(t, nil)

	before := decodeBody(t, do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if before["needs_bootstrap"] != true || before["authenticated"] != false {
		t.Fatalf("a fresh instance should ask for its first account: %v", before)
	}

	admin := h.signIn(t)

	after := decodeBody(t, admin.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if after["authenticated"] != true || after["can_administer"] != true {
		t.Fatalf("unexpected session: %v", after)
	}

	rec := do(t, h.internal, http.MethodPost, "/api/v1/auth/bootstrap",
		jsonBody(t, map[string]string{"email": "second@acme.example", "password": testPassword}), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a second bootstrap returned %d, want 403", rec.Code)
	}
}

func TestLoginLogoutAndSessionCookies(t *testing.T) {
	h := newHarness(t, nil)
	h.signIn(t)

	sess := &session{cookies: map[string]string{}}
	rec := sess.do(t, h.internal, http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": testAdminEmail, "password": testPassword}), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}

	// The session cookie must be HttpOnly; the CSRF one must not be, because
	// the interface has to read and echo it.
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "peek_session":
			sessionCookie = c
		case "peek_csrf":
			csrfCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected session cookie: %+v", sessionCookie)
	}
	if csrfCookie == nil || csrfCookie.HttpOnly {
		t.Fatalf("unexpected CSRF cookie: %+v", csrfCookie)
	}

	if rec := sess.do(t, h.internal, http.MethodPost, "/api/v1/auth/logout", nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	me := decodeBody(t, sess.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != false {
		t.Fatal("the session survived a logout")
	}
}

func TestWrongPasswordIsIndistinguishable(t *testing.T) {
	h := newHarness(t, nil)
	h.signIn(t)

	unknown := do(t, h.internal, http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": "nobody@acme.example", "password": testPassword}), nil)
	wrong := do(t, h.internal, http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": testAdminEmail, "password": "not-the-password"}), nil)

	if unknown.Code != http.StatusUnauthorized || wrong.Code != http.StatusUnauthorized {
		t.Fatalf("unknown=%d wrong=%d, both should be 401", unknown.Code, wrong.Code)
	}
	if unknown.Body.String() != wrong.Body.String() {
		t.Fatalf("the two answers differ:\n%s\n%s", unknown.Body.String(), wrong.Body.String())
	}
}

// TestCSRFIsRequired is the point of the double-submit cookie: a request that
// carries the session cookie but not the header is refused.
func TestCSRFIsRequired(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	withoutHeader := &session{cookies: map[string]string{
		"peek_session": admin.cookies["peek_session"],
	}}
	rec := withoutHeader.do(t, h.internal, http.MethodPost, "/api/v1/auth/password",
		jsonBody(t, map[string]string{"current": testPassword, "next": testOtherPassword}), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a request without the CSRF header returned %d, want 403", rec.Code)
	}

	wrongHeader := &session{cookies: withoutHeader.cookies, csrf: "not-the-token"}
	rec = wrongHeader.do(t, h.internal, http.MethodPost, "/api/v1/auth/password",
		jsonBody(t, map[string]string{"current": testPassword, "next": testOtherPassword}), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a wrong CSRF token returned %d, want 403", rec.Code)
	}

	// A GET needs no token.
	if rec := withoutHeader.do(t, h.internal, http.MethodGet, "/api/v1/auth/sessions", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("a GET was refused without a CSRF token: %d", rec.Code)
	}
}

func TestRolesGateTheAdminSurface(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	// Create a member and an auditor.
	for _, spec := range []struct{ email, role string }{
		{"member@acme.example", store.RoleMember},
		{"auditor@acme.example", store.RoleAuditor},
	} {
		rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/users", jsonBody(t, map[string]any{
			"email": spec.email, "role": spec.role, "password": testOtherPassword, "invite": false,
		}), nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", spec.role, rec.Code, rec.Body.String())
		}
	}

	member := h.signInAs(t, "member@acme.example", testOtherPassword)
	auditor := h.signInAs(t, "auditor@acme.example", testOtherPassword)

	cases := []struct {
		name   string
		sess   *session
		method string
		path   string
		body   []byte
		want   int
	}{
		{"member cannot list users", member, http.MethodGet, "/api/v1/users", nil, http.StatusForbidden},
		{"member cannot read the audit trail", member, http.MethodGet, "/api/v1/audit", nil, http.StatusForbidden},
		{"member cannot see the instance", member, http.MethodGet, "/api/v1/instance", nil, http.StatusForbidden},
		{"auditor reads the audit trail", auditor, http.MethodGet, "/api/v1/audit", nil, http.StatusOK},
		{"auditor cannot create users", auditor, http.MethodPost, "/api/v1/users",
			jsonBody(t, map[string]any{"email": "x@acme.example", "role": "member"}), http.StatusForbidden},
		{"auditor cannot create secrets", auditor, http.MethodPost, "/api/v1/secrets", nil, http.StatusForbidden},
		{"admin lists users", admin, http.MethodGet, "/api/v1/users", nil, http.StatusOK},
		{"admin reads the instance", admin, http.MethodGet, "/api/v1/instance", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if tc.path == "/api/v1/secrets" && body == nil {
				body = newClient(t, "", "x").createBody(t, nil)
			}
			rec := tc.sess.do(t, h.internal, tc.method, tc.path, body, nil)
			if rec.Code != tc.want {
				t.Fatalf("%s %s = %d, want %d: %s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestInvitationEndToEnd(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/users", jsonBody(t, map[string]any{
		"email": "invited@acme.example", "role": store.RoleManager, "invite": true,
	}), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	link, _ := body["link"].(string)
	if !strings.Contains(link, "/invitation#") {
		t.Fatalf("no usable invitation link: %v", body)
	}
	token := link[strings.Index(link, "#")+1:]

	preview := decodeBody(t, do(t, h.internal, http.MethodPost, "/api/v1/invitations/preview",
		jsonBody(t, map[string]string{"token": token}), nil))
	if preview["email"] != "invited@acme.example" || preview["new_account"] != true {
		t.Fatalf("unexpected preview: %v", preview)
	}

	invited := &session{cookies: map[string]string{}}
	rec = invited.do(t, h.internal, http.MethodPost, "/api/v1/invitations/accept",
		jsonBody(t, map[string]string{
			"token": token, "password": testOtherPassword, "display_name": "Nouvelle Personne",
		}), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	me := decodeBody(t, invited.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != true || me["can_manage"] != true {
		t.Fatalf("the invited manager is not signed in with their role: %v", me)
	}

	// The token is spent.
	rec = do(t, h.internal, http.MethodPost, "/api/v1/invitations/accept",
		jsonBody(t, map[string]string{"token": token, "password": testOtherPassword}), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an invitation was accepted twice: %d", rec.Code)
	}
}

func TestTOTPOverHTTP(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	start := decodeBody(t, admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/totp/start", nil, nil))
	secret, _ := start["secret"].(string)
	if secret == "" || !strings.HasPrefix(start["uri"].(string), "otpauth://") {
		t.Fatalf("unexpected enrolment: %v", start)
	}

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/totp/confirm",
		jsonBody(t, map[string]string{"code": "000000"}), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code returned %d", rec.Code)
	}

	confirmed := decodeBody(t, admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/totp/confirm",
		jsonBody(t, map[string]string{"code": totpCode(t, secret, time.Now())}), nil))
	codes, _ := confirmed["recovery_codes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("got %d recovery codes", len(codes))
	}

	// A new login now stops at the second factor.
	fresh := &session{cookies: map[string]string{}}
	login := decodeBody(t, fresh.do(t, h.internal, http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": testAdminEmail, "password": testPassword}), nil))
	if login["mfa_required"] != true {
		t.Fatalf("the second factor was not demanded: %v", login)
	}
	me := decodeBody(t, fresh.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != false || me["mfa_pending"] != true {
		t.Fatalf("a pending session looks signed in: %v", me)
	}
	// And a pending session reaches nothing else.
	if rec := fresh.do(t, h.internal, http.MethodGet, "/api/v1/dashboard/secrets", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a pending session reached the dashboard: %d", rec.Code)
	}

	rec = fresh.do(t, h.internal, http.MethodPost, "/api/v1/auth/mfa",
		jsonBody(t, map[string]string{"code": totpCode(t, secret, time.Now())}), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa: %d %s", rec.Code, rec.Body.String())
	}
	me = decodeBody(t, fresh.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != true {
		t.Fatalf("the promoted session is not signed in: %v", me)
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)
	other := h.signInAs(t, testAdminEmail, testPassword)

	listed := decodeBody(t, admin.do(t, h.internal, http.MethodGet, "/api/v1/auth/sessions", nil, nil))
	sessions, _ := listed["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("%d sessions listed, want 2", len(sessions))
	}

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/sessions/revoke-others", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke others: %d", rec.Code)
	}
	me := decodeBody(t, other.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != false {
		t.Fatal("the other session survived")
	}
	me = decodeBody(t, admin.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != true {
		t.Fatal("the current session was revoked too")
	}
}

func TestAccountSurfaceIsNotOnThePublicListener(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.PublicListen = "0.0.0.0:8081" })

	for _, probe := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodPost, "/api/v1/auth/bootstrap"},
		{http.MethodGet, "/api/v1/auth/me"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/dashboard/secrets"},
		{http.MethodGet, "/api/v1/audit/export"},
		{http.MethodPost, "/api/v1/auth/passkeys/login/start"},
	} {
		rec := do(t, h.public, probe.method, probe.path, []byte("{}"), nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s on the public listener returned %d, want 404", probe.method, probe.path, rec.Code)
		}
	}
}

func TestAuditExportCSV(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/audit/export?format=csv", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "peek-audit-") {
		t.Fatalf("content disposition %q", cd)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "at,event,secret_id,user_id,ip,user_agent,detail") {
		t.Fatalf("unexpected header line: %q", firstLine(body))
	}
	if !strings.Contains(body, "admin.user_created") && !strings.Contains(body, "auth.login") {
		t.Fatalf("the export holds no account events:\n%s", body)
	}

	jsonExport := admin.do(t, h.internal, http.MethodGet, "/api/v1/audit/export?format=json", nil, nil)
	if jsonExport.Code != http.StatusOK {
		t.Fatalf("json export: %d", jsonExport.Code)
	}
	if decodeBody(t, jsonExport)["count"] == nil {
		t.Fatal("the JSON export has no count")
	}
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)
	other := h.signInAs(t, testAdminEmail, testPassword)

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/auth/password",
		jsonBody(t, map[string]string{"current": testPassword, "next": testOtherPassword}), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body.String())
	}

	me := decodeBody(t, other.do(t, h.internal, http.MethodGet, "/api/v1/auth/me", nil, nil))
	if me["authenticated"] != false {
		t.Fatal("another session survived the password change")
	}
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return strings.TrimRight(s[:idx], "\r")
	}
	return s
}
