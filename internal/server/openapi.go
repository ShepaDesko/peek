package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// The OpenAPI 3.1 description of the API.
//
// It is built from the router, not written beside it. The route table is the
// only place a path exists, and a route with no operation here makes a test
// fail by name — which is the only way a specification document stays true
// after the sixth change nobody remembered to document.
//
// What is hand-written is the prose and the schemas: the parts a generator
// cannot invent. What is derived is every path, every method, and which
// listener serves it.

// operation is the hand-written half of one endpoint.
type operation struct {
	Summary     string
	Description string
	// Tag groups the operation in a documentation browser.
	Tag string
	// Scope is the API token scope this call needs, if any.
	Scope string
	// Public marks a route the recipient-facing listener also serves.
	Public bool
	// Session marks a route that refuses a bearer token.
	Session bool
	// Auth is the human description of what the caller must present.
	Auth string
	// RequestRef and ResponseRef name a component schema.
	RequestRef  string
	ResponseRef string
	// Responses adds status codes beyond the default pair.
	Responses map[string]string
	// Params documents path parameters beyond {id}, which is automatic.
	NoBody bool
}

// operations is the whole surface, keyed by "METHOD /path" exactly as chi
// reports it. Adding a route without adding a line here fails
// TestOpenAPICoversEveryRoute, which names the route it is missing.
var operations = map[string]operation{
	"GET /healthz": {
		Summary: "Liveness", Tag: "health", Public: true, NoBody: true,
		Description: "Returns `ok`. Cheap enough for a load balancer to poll.",
		Auth:        "none",
	},
	"GET /readyz": {
		Summary: "Readiness", Tag: "health", Public: true, NoBody: true,
		Description: "503 when a dependency is unavailable. Point your load balancer here.",
		Auth:        "none", ResponseRef: "Readiness",
	},
	"GET /robots.txt": {
		Summary: "Robots policy", Tag: "health", Public: true, NoBody: true,
		Description: "Disallows everything: a secret link must never be indexed.",
		Auth:        "none",
	},
	"GET /branding.css": {
		Summary: "Theme as CSS", Tag: "branding", Public: true, NoBody: true,
		Description: "The instance theme as CSS custom properties. Supports If-None-Match.",
		Auth:        "none",
	},
	"GET /branding/{kind}": {
		Summary: "Brand asset", Tag: "branding", Public: true, NoBody: true,
		Description: "Logo, dark logo or favicon. `kind` is one of `logo`, `logo_dark`, `favicon`.",
		Auth:        "none",
	},
	"GET /api/v1/branding": {
		Summary: "Theme as JSON", Tag: "branding", Public: true, NoBody: true,
		Description: "The resolved theme, with an ETag.", Auth: "none",
	},
	"GET /api/v1/ip": {
		Summary: "Resolved client address", Tag: "diagnostics", Public: true, NoBody: true,
		Description: "What Peek believes your address is, and whether your proxy is trusted. " +
			"The fastest way to find out whether a reverse-proxy configuration works.",
		Auth: "none", ResponseRef: "ClientAddress",
	},
	"GET /api/v1/policy": {
		Summary: "Instance limits", Tag: "policy", NoBody: true,
		Description: "Everything a client must respect: expiry and read ceilings, size limits, " +
			"the KDF parameters to use, and the chunk size for files.",
		Auth: "session or token", ResponseRef: "Policy",
	},

	// --- secrets, recipient side -------------------------------------------
	"GET /api/v1/secrets/{id}": {
		Summary: "Secret metadata", Tag: "secrets", Public: true, NoBody: true,
		Description: "What a recipient may see before proving possession of the key. " +
			"**No read is consumed**, which is what makes link-preview bots harmless.",
		Auth: "none", ResponseRef: "SecretMeta",
		Responses: map[string]string{"404": "Unknown, expired, consumed or burned — deliberately indistinguishable."},
	},
	"POST /api/v1/secrets/{id}/reveal": {
		Summary: "Reveal a secret", Tag: "secrets", Public: true,
		Description: "Consumes one read and returns the sealed payload. A wrong token costs no " +
			"read; once the attempt budget is exhausted the secret is destroyed.",
		Auth:       "the read token, derived from the key in the link fragment",
		RequestRef: "RevealRequest", ResponseRef: "Reveal",
		Responses: map[string]string{
			"403": "Wrong read token or passphrase; carries `attempts_left`.",
			"410": "Destroyed after too many failed attempts.",
		},
	},
	"DELETE /api/v1/secrets/{id}": {
		Summary: "Recipient deletion", Tag: "secrets", Public: true, NoBody: true,
		Description: "Destroys the secret, when the sender allowed it. The read token goes in " +
			"`X-Peek-Token` so it stays out of proxy logs.",
		Auth: "the read token", Responses: map[string]string{"204": "Destroyed.", "404": "Not allowed, or already gone."},
	},

	// --- attachments --------------------------------------------------------
	"GET /api/v1/files/{id}": {
		Summary: "Download an attachment", Tag: "files", Public: true, NoBody: true,
		Description: "Streams one encrypted blob. Needs the download grant a successful reveal " +
			"handed out, in `X-Peek-Download`. Everything that can go wrong answers 404.",
		Auth: "a download grant",
	},
	"HEAD /api/v1/files/{id}": {
		Summary: "Attachment size", Tag: "files", Public: true, NoBody: true,
		Description: "The headers of the download, without the body.",
		Auth:        "a download grant",
	},
	"POST /api/v1/files": {
		Summary: "Upload an attachment", Tag: "files", Scope: store.ScopeSecretsWrite,
		Description: "Accepts an already-encrypted stream. `Content-Length` is required: the " +
			"storage backend writes exactly that many bytes. Returns the blob id and the claim " +
			"token that attaches it to a secret.",
		Auth: "session or token", ResponseRef: "Upload",
		Responses: map[string]string{
			"411": "No Content-Length.",
			"413": "Larger than `policy.max_file_bytes`.",
			"503": "No file storage configured.",
		},
	},

	// --- secrets, sender side ----------------------------------------------
	"POST /api/v1/secrets": {
		Summary: "Create a secret", Tag: "secrets", Scope: store.ScopeSecretsWrite,
		Description: "One secret, or a bundle of recipient links sharing one set of attachments. " +
			"Everything in the body is already ciphertext or a digest: the server sees no key.",
		Auth: "session or token", RequestRef: "CreateSecret", ResponseRef: "Created",
		Responses: map[string]string{"409": "Identifier already used.", "422": "Refused by policy."},
	},
	"GET /api/v1/secrets/{id}/receipt": {
		Summary: "Sender receipt", Tag: "secrets", Scope: store.ScopeSecretsManage, NoBody: true,
		Description: "Status of a secret, alive or not: it keeps answering from the tombstone.",
		Auth:        "the receipt token in `X-Peek-Token`", ResponseRef: "Receipt",
	},
	"POST /api/v1/secrets/{id}/burn": {
		Summary: "Burn a secret", Tag: "secrets", Scope: store.ScopeSecretsManage,
		Description: "Destroys it immediately. Answers 204.",
		Auth:        "the receipt token",
	},
	"POST /api/v1/secrets/{id}/email": {
		Summary: "E-mail the link", Tag: "secrets", Scope: store.ScopeSecretsManage,
		Description: "Sends the recipient link by e-mail. The passphrase is never included.",
		Auth:        "the receipt token", RequestRef: "SendLink",
	},

	// --- secret requests ----------------------------------------------------
	"POST /api/v1/requests": {
		Summary: "Open a secret request", Tag: "requests", Scope: store.ScopeSecretsWrite,
		Description: "\"Send me the password for X\". Stores the requester's P-256 public key so " +
			"a deposit can be sealed to it; the private half never leaves their own link.",
		Auth: "session or token", RequestRef: "CreateRequest", ResponseRef: "RequestCreated",
	},
	"GET /api/v1/requests/{id}": {
		Summary: "Request metadata", Tag: "requests", Public: true, NoBody: true,
		Description: "What a depositor may see before proving possession of the request key.",
		Auth:        "none", ResponseRef: "RequestMeta",
	},
	"POST /api/v1/requests/{id}/open": {
		Summary: "Read the prompt", Tag: "requests", Public: true,
		Description: "Releases the sealed prompt. Consumes nothing: the prompt is not the answer.",
		Auth:        "the request key from the deposit link", RequestRef: "OpenRequest", ResponseRef: "RequestOpened",
	},
	"POST /api/v1/requests/{id}/deposit": {
		Summary: "Answer a request", Tag: "requests", Public: true,
		Description: "An ordinary secret, plus its content key wrapped to the requester's public " +
			"key with ECIES. The counter and the secret move together, so a single-use request " +
			"accepts exactly one answer even across nodes.",
		Auth: "the request key", RequestRef: "Deposit", ResponseRef: "Deposited",
		Responses: map[string]string{"410": "Already answered as many times as it accepts."},
	},
	"GET /api/v1/requests/{id}/receipt": {
		Summary: "Follow a request", Tag: "requests", Scope: store.ScopeSecretsManage, NoBody: true,
		Description: "The requester's own view, with every wrapped key received so far.",
		Auth:        "the request receipt token", ResponseRef: "RequestReceipt",
	},
	"POST /api/v1/requests/{id}/receipt": {
		Summary: "Follow a request (body form)", Tag: "requests", Scope: store.ScopeSecretsManage,
		Description: "Same as the GET, with the token in the body rather than a header.",
		Auth:        "the request receipt token", ResponseRef: "RequestReceipt",
	},
	"DELETE /api/v1/requests/{id}": {
		Summary: "Close a request", Tag: "requests", Scope: store.ScopeSecretsManage, NoBody: true,
		Description: "No new answer can arrive. Answers already received keep their own " +
			"lifecycle: closing the door does not burn what is inside.",
		Auth: "the request receipt token",
	},

	// --- sign-in ------------------------------------------------------------
	"POST /api/v1/auth/login": {
		Summary: "Sign in", Tag: "auth", Session: true,
		Description: "E-mail and password. Answers `mfa_required` when a second factor is due.",
		Auth:        "none", RequestRef: "Login",
	},
	"POST /api/v1/auth/mfa": {
		Summary: "Second factor", Tag: "auth", Session: true,
		Description: "A TOTP code or a recovery code, finishing a pending sign-in.",
		Auth:        "a pending session",
	},
	"POST /api/v1/auth/bootstrap": {
		Summary: "Create the first administrator", Tag: "auth", Session: true,
		Description: "Served only while the instance has no account at all.",
		Auth:        "none",
	},
	"POST /api/v1/auth/password/forgot": {
		Summary: "Request a reset", Tag: "auth", Session: true,
		Description: "Always answers the same, whether or not the address exists.",
		Auth:        "none",
	},
	"POST /api/v1/auth/password/reset": {
		Summary: "Reset a password", Tag: "auth", Session: true,
		Description: "With the token from the e-mail.", Auth: "a reset token",
	},
	"POST /api/v1/auth/passkeys/login/start":  {Summary: "Begin a passkey sign-in", Tag: "auth", Session: true, Auth: "none"},
	"POST /api/v1/auth/passkeys/login/finish": {Summary: "Finish a passkey sign-in", Tag: "auth", Session: true, Auth: "a passkey challenge"},
	"POST /api/v1/invitations/preview":        {Summary: "Preview an invitation", Tag: "auth", Session: true, Auth: "an invitation token"},
	"POST /api/v1/invitations/accept":         {Summary: "Accept an invitation", Tag: "auth", Session: true, Auth: "an invitation token"},
	"GET /api/v1/auth/me": {
		Summary: "Who am I", Tag: "auth", NoBody: true, Session: true,
		Description: "The signed-in account and what it may do.", Auth: "session",
	},
	"POST /api/v1/auth/logout": {Summary: "Sign out", Tag: "auth", Session: true, Auth: "session"},

	// --- account ------------------------------------------------------------
	"POST /api/v1/auth/password":                 {Summary: "Change password", Tag: "account", Session: true, Auth: "session"},
	"POST /api/v1/auth/totp/start":               {Summary: "Begin TOTP enrolment", Tag: "account", Session: true, Auth: "session"},
	"POST /api/v1/auth/totp/confirm":             {Summary: "Confirm TOTP", Tag: "account", Session: true, Auth: "session"},
	"POST /api/v1/auth/totp/disable":             {Summary: "Disable TOTP", Tag: "account", Session: true, Auth: "session"},
	"POST /api/v1/auth/recovery-codes":           {Summary: "Reissue recovery codes", Tag: "account", Session: true, Auth: "session"},
	"GET /api/v1/auth/sessions":                  {Summary: "Active sessions", Tag: "account", NoBody: true, Session: true, Auth: "session"},
	"DELETE /api/v1/auth/sessions/{id}":          {Summary: "Revoke a session", Tag: "account", NoBody: true, Session: true, Auth: "session"},
	"POST /api/v1/auth/sessions/revoke-others":   {Summary: "Revoke every other session", Tag: "account", Session: true, Auth: "session"},
	"GET /api/v1/auth/passkeys":                  {Summary: "List passkeys", Tag: "account", NoBody: true, Session: true, Auth: "session"},
	"POST /api/v1/auth/passkeys/register/start":  {Summary: "Begin passkey registration", Tag: "account", Session: true, Auth: "session"},
	"POST /api/v1/auth/passkeys/register/finish": {Summary: "Finish passkey registration", Tag: "account", Session: true, Auth: "session"},
	"PATCH /api/v1/auth/passkeys/{id}":           {Summary: "Rename a passkey", Tag: "account", Session: true, Auth: "session"},
	"DELETE /api/v1/auth/passkeys/{id}":          {Summary: "Remove a passkey", Tag: "account", NoBody: true, Session: true, Auth: "session"},
	"GET /api/v1/auth/tokens":                    {Summary: "List API tokens", Tag: "tokens", NoBody: true, Session: true, Auth: "session", ResponseRef: "TokenList"},
	"POST /api/v1/auth/tokens":                   {Summary: "Create an API token", Tag: "tokens", Session: true, Auth: "session", RequestRef: "CreateToken", ResponseRef: "TokenCreated", Description: "The clear text is in the response and nowhere else, ever."},
	"DELETE /api/v1/auth/tokens/{id}":            {Summary: "Revoke an API token", Tag: "tokens", NoBody: true, Session: true, Auth: "session"},
	"GET /api/v1/dashboard/secrets":              {Summary: "Own secrets", Tag: "account", NoBody: true, Session: true, Auth: "session"},
	"GET /api/v1/dashboard/requests":             {Summary: "Own secret requests", Tag: "account", NoBody: true, Session: true, Auth: "session"},
	"POST /api/v1/dashboard/secrets/{id}/burn":   {Summary: "Burn an owned secret", Tag: "account", Session: true, Auth: "session"},

	// --- administration -----------------------------------------------------
	"GET /api/v1/users":                {Summary: "List accounts", Tag: "admin", NoBody: true, Session: true, Auth: "session, manager"},
	"POST /api/v1/users":               {Summary: "Create or invite an account", Tag: "admin", Session: true, Auth: "session, manager"},
	"PATCH /api/v1/users/{id}":         {Summary: "Update an account", Tag: "admin", Session: true, Auth: "session, manager"},
	"DELETE /api/v1/users/{id}":        {Summary: "Delete an account", Tag: "admin", NoBody: true, Session: true, Auth: "session, manager"},
	"POST /api/v1/users/{id}/password": {Summary: "Set a password", Tag: "admin", Session: true, Auth: "session, manager"},
	"DELETE /api/v1/users/{id}/sso": {
		Summary: "Unlink a directory identity", Tag: "admin", NoBody: true, Session: true,
		Description: "The way out of a subject linked to the wrong account — a reassigned " +
			"mailbox, a tenant migration, a mistake. The next sign-in links it afresh. " +
			"Refused with `409` when the account has no password, because unlinking would " +
			"leave no way in.",
		Auth: "session, manager",
	},
	"GET /api/v1/invitations":         {Summary: "Pending invitations", Tag: "admin", NoBody: true, Session: true, Auth: "session, manager"},
	"DELETE /api/v1/invitations/{id}": {Summary: "Revoke an invitation", Tag: "admin", NoBody: true, Session: true, Auth: "session, manager"},
	"GET /api/v1/audit": {
		Summary: "Read the audit trail", Tag: "audit", Scope: store.ScopeAuditRead, NoBody: true,
		Description: "Filterable by secret and by event. Secret content never appears, and a " +
			"test asserts it.",
		Auth: "session or token, manager or auditor", ResponseRef: "AuditPage",
	},
	"GET /api/v1/audit/export": {
		Summary: "Export the audit trail", Tag: "audit", Scope: store.ScopeAuditRead, NoBody: true,
		Description: "The same trail as CSV or NDJSON, for a SIEM that pulls.",
		Auth:        "session or token, manager or auditor",
	},
	"GET /api/v1/instance": {
		Summary: "Instance status", Tag: "admin", Scope: store.ScopeInstanceRead, NoBody: true,
		Description: "Version, driver, uptime and live secret count.",
		Auth:        "session or token, administrator", ResponseRef: "Instance",
	},
	"GET /api/v1/auth/sso": {
		Summary: "Single sign-on, as the sign-in page sees it", Tag: "auth", NoBody: true,
		Description: "Whether a provider is configured, what the button should say, and " +
			"whether local sign-in is refused. Read before anybody has signed in, so it " +
			"takes no authentication and says nothing a visitor could not infer from the " +
			"button.",
		Auth: "none", ResponseRef: "SSOInfo",
	},
	"GET /auth/sso": {
		Summary: "Start a single sign-on", Tag: "auth", NoBody: true,
		Description: "Browser navigation, not an API call: answers `302` to the identity " +
			"provider and sets a sealed, single-use cookie holding the state, the nonce and " +
			"the PKCE verifier. `return` may name a path on this instance to come back to; " +
			"anything else becomes `/`.",
		Auth:      "none",
		Responses: map[string]string{"302": "To the identity provider, or to /login?sso_error=… when it cannot be reached."},
	},
	"GET /auth/sso/callback": {
		Summary: "Finish a single sign-on", Tag: "auth", NoBody: true,
		Description: "Where the identity provider sends the browser back. Verifies the " +
			"state against the cookie, exchanges the code over the back channel, verifies " +
			"the assertion, then sets the same session cookie a password sign-in would. " +
			"Every refusal becomes `302 /login?sso_error=<code>`: the detail goes to the " +
			"audit trail and the log, never into a query string.",
		Auth:      "none",
		Responses: map[string]string{"302": "To the interface on success, to /login?sso_error=… otherwise."},
	},
	"GET /api/v1/webhooks": {
		Summary: "Webhook endpoints and queue", Tag: "webhooks", Scope: store.ScopeInstanceRead, NoBody: true,
		Description: "What is configured, how the signature is computed, and how many " +
			"deliveries are owed, delivered or given up on. There is no call that *creates* " +
			"an endpoint: a URL the API could set would turn this server into a request " +
			"forwarder aimed at your own network, so endpoints live in `peek.toml`.",
		Auth: "session or token, administrator", ResponseRef: "Webhooks",
	},
	"GET /api/v1/webhooks/deliveries": {
		Summary: "The delivery queue", Tag: "webhooks", Scope: store.ScopeInstanceRead, NoBody: true,
		Description: "Filter with `state` (pending, delivered, failed), `endpoint`, `event` " +
			"and `limit`. The body of a delivery is not returned: it is the signed bytes, and " +
			"it belongs to the receiver.",
		Auth: "session or token, administrator", ResponseRef: "Deliveries",
	},
	"POST /api/v1/webhooks/{name}/test": {
		Summary: "Send a test delivery", Tag: "webhooks", Session: true,
		Description: "Sends one `peek.ping` synchronously and answers with what the receiver " +
			"said, so the path can be proven without reading a real secret. Answers 200 with " +
			"`ok: false` when the receiver refused: the call worked, the delivery did not.",
		Auth: "session, administrator",
	},
	"POST /api/v1/webhooks/retry": {
		Summary: "Requeue failed deliveries", Tag: "webhooks", Session: true,
		Description: "With no body, every delivery that ran out of attempts goes back in the " +
			"queue. `endpoint` narrows it to one; `id` to a single delivery.",
		Auth: "session, administrator",
	},
	"GET /api/v1/branding/admin":            {Summary: "Brand as stored", Tag: "branding", NoBody: true, Session: true, Auth: "session, administrator"},
	"PUT /api/v1/branding/admin":            {Summary: "Save the brand", Tag: "branding", Session: true, Auth: "session, administrator"},
	"DELETE /api/v1/branding/admin":         {Summary: "Reset the brand", Tag: "branding", NoBody: true, Session: true, Auth: "session, administrator"},
	"PUT /api/v1/branding/assets/{kind}":    {Summary: "Upload a brand asset", Tag: "branding", Session: true, Auth: "session, administrator"},
	"DELETE /api/v1/branding/assets/{kind}": {Summary: "Remove a brand asset", Tag: "branding", NoBody: true, Session: true, Auth: "session, administrator"},
	"POST /api/v1/branding/test-email":      {Summary: "Send a test e-mail", Tag: "branding", Session: true, Auth: "session, administrator"},
	"GET /api/v1/openapi.json": {
		Summary: "This document", Tag: "diagnostics", NoBody: true,
		Description: "The OpenAPI 3.1 description of this instance, generated from its own " +
			"route table. A route with no description makes a test fail, which is how it stays " +
			"true.",
		Auth: "none",
	},
}

// RouteKeys returns every "METHOD /path" chi serves on the internal listener,
// which is the superset of both listeners.
func (s *Server) RouteKeys() ([]string, error) {
	routes, ok := s.Handler(listenerInternal).(chi.Routes)
	if !ok {
		return nil, fmt.Errorf("openapi: the handler is not walkable")
	}
	var keys []string
	err := chi.Walk(routes,
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			route = strings.TrimSuffix(route, "/")
			if route == "" {
				route = "/"
			}
			keys = append(keys, method+" "+route)
			return nil
		})
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

// OpenAPI builds the document for this instance.
func (s *Server) OpenAPI() (map[string]any, error) {
	keys, err := s.RouteKeys()
	if err != nil {
		return nil, err
	}

	paths := map[string]any{}
	var missing []string
	for _, key := range keys {
		method, route, _ := strings.Cut(key, " ")
		op, ok := operations[key]
		if !ok {
			missing = append(missing, key)
			continue
		}
		item, _ := paths[route].(map[string]any)
		if item == nil {
			item = map[string]any{}
			if strings.Contains(route, "{") {
				item["parameters"] = pathParameters(route)
			}
			paths[route] = item
		}
		item[strings.ToLower(method)] = s.operationObject(op)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("openapi: no description for %s", strings.Join(missing, ", "))
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Peek",
			"version": s.version,
			"summary": "Ephemeral secret sharing, encrypted in the browser.",
			"description": "Every byte of content in this API is already encrypted when it " +
				"arrives and still encrypted when it leaves. The server holds ciphertext, " +
				"digests and counters; the keys live in URL fragments, which browsers do not " +
				"transmit.\n\nWriting a client means implementing format v1: start from " +
				"docs/CRYPTO.md and make crypto/vectors/v1.json pass.",
			"license": map[string]any{"name": "Proprietary"},
		},
		"servers": []any{map[string]any{"url": strings.TrimRight(s.cfg.PublicURL, "/")}},
		"tags": []any{
			map[string]any{"name": "health", "description": "Liveness and readiness."},
			map[string]any{"name": "diagnostics", "description": "What the server thinks of your network."},
			map[string]any{"name": "policy", "description": "The limits a client must respect."},
			map[string]any{"name": "secrets", "description": "Creating, revealing and burning."},
			map[string]any{"name": "files", "description": "Encrypted attachments."},
			map[string]any{"name": "requests", "description": "Asking someone for a secret."},
			map[string]any{"name": "auth", "description": "Signing in."},
			map[string]any{"name": "account", "description": "Your own account."},
			map[string]any{"name": "tokens", "description": "API tokens, for scripts."},
			map[string]any{"name": "audit", "description": "The append-only trail."},
			map[string]any{"name": "admin", "description": "Accounts and the instance."},
			map[string]any{"name": "branding", "description": "White-labelling."},
			map[string]any{"name": "webhooks", "description": "Outbound notifications."},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerToken": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "`Authorization: Bearer peek_<id>.<secret>`. A token never " +
						"exceeds its owner's role; scopes narrow it further.",
				},
				"sessionCookie": map[string]any{
					"type": "apiKey", "in": "cookie", "name": sessionCookie,
					"description": "The interface's session. State-changing calls must also echo " +
						"the `peek_csrf` cookie in `X-Peek-CSRF`.",
				},
			},
			"schemas": openAPISchemas(),
		},
		"paths": paths,
	}, nil
}

func (s *Server) operationObject(op operation) map[string]any {
	out := map[string]any{
		"summary": op.Summary,
		"tags":    []any{op.Tag},
	}

	var notes []string
	if op.Description != "" {
		notes = append(notes, op.Description)
	}
	if op.Auth != "" {
		notes = append(notes, "**Authentication**: "+op.Auth+".")
	}
	if op.Scope != "" {
		notes = append(notes, "**Token scope**: `"+op.Scope+"`.")
	}
	if op.Session {
		notes = append(notes, "**Refuses API tokens**: this call needs a signed-in person.")
	}
	listener := "Internal listener only."
	if op.Public {
		listener = "Served on both listeners."
	}
	notes = append(notes, listener)
	out["description"] = strings.Join(notes, "\n\n")

	if op.RequestRef != "" {
		out["requestBody"] = map[string]any{
			"required": true,
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": "#/components/schemas/" + op.RequestRef},
				},
			},
		}
	}

	responses := map[string]any{}
	ok := map[string]any{"description": "Success."}
	if op.ResponseRef != "" {
		ok["content"] = map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/" + op.ResponseRef},
			},
		}
	}
	responses["200"] = ok
	for code, desc := range op.Responses {
		responses[code] = map[string]any{
			"description": desc,
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": "#/components/schemas/Error"},
				},
			},
		}
	}
	if _, has := responses["429"]; !has {
		responses["429"] = map[string]any{
			"description": "Rate limited; see `Retry-After`.",
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": "#/components/schemas/Error"},
				},
			},
		}
	}
	out["responses"] = responses

	switch {
	case op.Session:
		out["security"] = []any{map[string]any{"sessionCookie": []any{}}}
	case op.Scope != "":
		out["security"] = []any{
			map[string]any{"sessionCookie": []any{}},
			map[string]any{"bearerToken": []any{op.Scope}},
		}
	}
	return out
}

func pathParameters(route string) []any {
	var params []any
	for _, part := range strings.Split(route, "/") {
		if !strings.HasPrefix(part, "{") {
			continue
		}
		name := strings.Trim(part, "{}")
		schema := map[string]any{"type": "string"}
		switch name {
		case "id":
			schema["pattern"] = "^[A-Za-z0-9_-]{22}$"
			schema["description"] = "A public identifier: 128 random bits, base64url."
		case "name":
			schema["description"] = "The endpoint name from peek.toml."
		case "kind":
			schema["description"] = "Which asset: logo, logo_dark, favicon or email_logo."
		}
		params = append(params, map[string]any{
			"name": name, "in": "path", "required": true, "schema": schema,
		})
	}
	return params
}

// ref names a component schema. The coverage test resolves every one of these,
// so a typo here is a failing test rather than a client generator that quietly
// produces a half-typed model.
func ref(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func b64Field(description string) map[string]any {
	return map[string]any{"type": "string", "description": description + " base64url, unpadded."}
}

func openAPISchemas() map[string]any {
	kdf := map[string]any{
		"type":        "object",
		"description": "Argon2id parameters. The salt is public; it is useless without the key.",
		"required":    []any{"salt", "memory_kib", "iterations", "parallelism"},
		"properties": map[string]any{
			"salt":        b64Field("16 bytes of salt."),
			"memory_kib":  map[string]any{"type": "integer", "minimum": 8192, "default": pcrypto.DefaultMemoryKiB},
			"iterations":  map[string]any{"type": "integer", "minimum": 1, "default": pcrypto.DefaultIterations},
			"parallelism": map[string]any{"type": "integer", "minimum": 1, "default": pcrypto.DefaultParallelism},
		},
	}
	recipient := map[string]any{
		"type":     "object",
		"required": []any{"id", "kind", "ciphertext", "read_token_hash", "receipt_token_hash", "kdf"},
		"properties": map[string]any{
			"id":                     map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{22}$"},
			"kind":                   map[string]any{"type": "string", "enum": []any{"text", "url", "file"}},
			"ciphertext":             b64Field("Nonce followed by the AES-256-GCM payload."),
			"read_token_hash":        b64Field("SHA-256 of the read token."),
			"receipt_token_hash":     b64Field("SHA-256 of the sender's receipt token."),
			"kdf":                    kdf,
			"has_passphrase":         map[string]any{"type": "boolean"},
			"ttl_seconds":            map[string]any{"type": "integer"},
			"views":                  map[string]any{"type": "integer", "minimum": 1},
			"retrieval_step":         map[string]any{"type": "boolean", "default": true},
			"deletable_by_recipient": map[string]any{"type": "boolean"},
			"label_enc":              b64Field("Sender-only label, sealed client side."),
			"notify_email":           map[string]any{"type": "string", "format": "email"},
		},
	}
	fileClaim := map[string]any{
		"type":     "object",
		"required": []any{"id", "token"},
		"properties": map[string]any{
			"id":    map[string]any{"type": "string"},
			"token": b64Field("The claim token returned by the upload."),
		},
	}

	return map[string]any{
		"Error": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"error": map[string]any{
					"type":     "object",
					"required": []any{"code", "message"},
					"properties": map[string]any{
						"code":          map[string]any{"type": "string"},
						"message":       map[string]any{"type": "string"},
						"field":         map[string]any{"type": "string"},
						"attempts_left": map[string]any{"type": "integer"},
					},
				},
			},
		},
		"Readiness": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"ready": map[string]any{"type": "boolean"},
				"checks": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name": map[string]any{"type": "string"},
						"ok":   map[string]any{"type": "boolean"},
					},
				}},
			},
		},
		"ClientAddress": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"client_ip":          map[string]any{"type": "string"},
				"peer_addr":          map[string]any{"type": "string"},
				"scheme":             map[string]any{"type": "string"},
				"host":               map[string]any{"type": "string"},
				"listener":           map[string]any{"type": "string", "enum": []any{"internal", "public"}},
				"trusted_peer":       map[string]any{"type": "boolean"},
				"forwarded_honoured": map[string]any{"type": "boolean"},
			},
		},
		"Policy": map[string]any{
			"type":                 "object",
			"description":          "The ceilings a client must respect, and the KDF parameters to use.",
			"additionalProperties": true,
		},
		"SecretMeta": map[string]any{
			"type":        "object",
			"description": "Deliberately says nothing about the content.",
			"properties": map[string]any{
				"id":                     map[string]any{"type": "string"},
				"kind":                   map[string]any{"type": "string"},
				"has_passphrase":         map[string]any{"type": "boolean"},
				"retrieval_step":         map[string]any{"type": "boolean"},
				"deletable_by_recipient": map[string]any{"type": "boolean"},
				"views_remaining":        map[string]any{"type": "integer"},
				"views_max":              map[string]any{"type": "integer"},
				"expires_at":             map[string]any{"type": "string", "format": "date-time"},
				"size_bytes":             map[string]any{"type": "integer"},
				"attempts_left":          map[string]any{"type": "integer"},
				"kdf":                    kdf,
			},
		},
		"RevealRequest": map[string]any{
			"type": "object", "required": []any{"read_token"},
			"properties": map[string]any{"read_token": b64Field("32 bytes, derived from the key in the fragment.")},
		},
		"Reveal": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind":            map[string]any{"type": "string"},
				"ciphertext":      b64Field("Nonce followed by the sealed payload."),
				"views_remaining": map[string]any{"type": "integer"},
				"destroyed":       map[string]any{"type": "boolean"},
				"size_bytes":      map[string]any{"type": "integer"},
				"download_token": b64Field("Present when the secret has attachments: the grant " +
					"that fetches them, valid for `policy.download_window`."),
				"download_expires_at": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"CreateSecret": map[string]any{
			"description": "Either one recipient inline, or a `recipients` list. Both at once is " +
				"refused: it would be ambiguous which settings apply.",
			"allOf": []any{recipient},
			"type":  "object",
			"properties": map[string]any{
				"recipients": map[string]any{"type": "array", "items": recipient,
					"description": "Several links sharing one set of attachments."},
				"files": map[string]any{"type": "array", "items": fileClaim,
					"description": "Attachments, declared once for the whole bundle."},
			},
		},
		"Created": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":         map[string]any{"type": "string"},
				"kind":       map[string]any{"type": "string"},
				"views_max":  map[string]any{"type": "integer"},
				"expires_at": map[string]any{"type": "string", "format": "date-time"},
				"created_at": map[string]any{"type": "string", "format": "date-time"},
				"url": map[string]any{"type": "string", "format": "uri",
					"description": "The recipient page. The key goes in the fragment, client side."},
				"bundle_id": map[string]any{"type": "string"},
			},
		},
		"Receipt": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":              map[string]any{"type": "string"},
				"status":          map[string]any{"type": "string", "enum": []any{"active", "viewed", "expired", "burned", "deleted", "locked"}},
				"views_used":      map[string]any{"type": "integer"},
				"views_max":       map[string]any{"type": "integer"},
				"views_remaining": map[string]any{"type": "integer"},
				"created_at":      map[string]any{"type": "string", "format": "date-time"},
				"expires_at":      map[string]any{"type": "string", "format": "date-time"},
				"last_viewed_at":  map[string]any{"type": "string", "format": "date-time"},
				"has_passphrase":  map[string]any{"type": "boolean"},
			},
		},
		"SendLink": map[string]any{
			"type": "object", "required": []any{"to"},
			"properties": map[string]any{
				"to":      map[string]any{"type": "string", "format": "email"},
				"message": map[string]any{"type": "string"},
				"link": map[string]any{"type": "string",
					"description": "The full link including its fragment. The server strips the " +
						"fragment before storing anything."},
			},
		},
		"Upload": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":    map[string]any{"type": "string"},
				"token": b64Field("The claim token. Shown once; attaching needs it."),
				"size":  map[string]any{"type": "integer"},
				"expires_at": map[string]any{"type": "string", "format": "date-time",
					"description": "After this, an unclaimed blob is collected."},
			},
		},
		"CreateRequest": map[string]any{
			"type":     "object",
			"required": []any{"id", "public_key", "read_token_hash", "receipt_token_hash", "kdf"},
			"properties": map[string]any{
				"id":                 map[string]any{"type": "string"},
				"public_key":         b64Field("65 bytes: an uncompressed SEC1 P-256 point."),
				"read_token_hash":    b64Field("SHA-256 of the request read token."),
				"receipt_token_hash": b64Field("SHA-256 of the requester's receipt token."),
				"prompt_enc":         b64Field("The prompt, sealed with the request key."),
				"kdf":                kdf,
				"label_enc":          b64Field("Private label."),
				"ttl_seconds":        map[string]any{"type": "integer"},
				"max_deposits":       map[string]any{"type": "integer", "minimum": 1},
				"notify_email":       map[string]any{"type": "string", "format": "email"},
			},
		},
		"RequestCreated": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":           map[string]any{"type": "string"},
				"max_deposits": map[string]any{"type": "integer"},
				"expires_at":   map[string]any{"type": "string", "format": "date-time"},
				"created_at":   map[string]any{"type": "string", "format": "date-time"},
				"url":          map[string]any{"type": "string", "format": "uri"},
			},
		},
		"RequestMeta": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":                 map[string]any{"type": "string"},
				"deposits_remaining": map[string]any{"type": "integer"},
				"expires_at":         map[string]any{"type": "string", "format": "date-time"},
				"kdf":                kdf,
			},
		},
		"OpenRequest": map[string]any{
			"type": "object", "required": []any{"read_token"},
			"properties": map[string]any{"read_token": b64Field("Derived from the request key in the link.")},
		},
		"RequestOpened": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":         map[string]any{"type": "string"},
				"prompt_enc": b64Field("The sealed prompt."),
				"expires_at": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Deposit": map[string]any{
			"type":     "object",
			"required": []any{"read_token", "wrapped_key", "secret"},
			"properties": map[string]any{
				"read_token": b64Field("Derived from the request key."),
				"wrapped_key": b64Field("125 bytes: the ephemeral public key, the nonce and the " +
					"content key sealed to the requester."),
				"secret": recipient,
				"files":  map[string]any{"type": "array", "items": fileClaim},
			},
		},
		"Deposited": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":         map[string]any{"type": "string"},
				"created_at": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"RequestReceipt": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":                 map[string]any{"type": "string"},
				"max_deposits":       map[string]any{"type": "integer"},
				"deposits_used":      map[string]any{"type": "integer"},
				"deposits_remaining": map[string]any{"type": "integer"},
				"deposits": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"secret_id":       map[string]any{"type": "string"},
						"wrapped_key":     b64Field("Unwrap it with the private key from your own link."),
						"kdf":             kdf,
						"has_passphrase":  map[string]any{"type": "boolean"},
						"size_bytes":      map[string]any{"type": "integer"},
						"created_at":      map[string]any{"type": "string", "format": "date-time"},
						"views_remaining": map[string]any{"type": "integer"},
					},
				}},
			},
		},
		"Login": map[string]any{
			"type": "object", "required": []any{"email", "password"},
			"properties": map[string]any{
				"email":    map[string]any{"type": "string", "format": "email"},
				"password": map[string]any{"type": "string", "format": "password"},
			},
		},
		"CreateToken": map[string]any{
			"type": "object", "required": []any{"name", "scopes"},
			"properties": map[string]any{
				"name": map[string]any{"type": "string", "maxLength": 80},
				"scopes": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{
					"type": "string", "enum": toAny(store.AllScopes),
				}},
				"ttl_seconds": map[string]any{"type": "integer", "description": "0 means no expiry."},
			},
		},
		"TokenCreated": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":   map[string]any{"type": "string"},
				"name": map[string]any{"type": "string"},
				"token": map[string]any{"type": "string",
					"description": "`peek_<id>.<secret>`. The only time the clear text exists " +
						"outside your own storage."},
				"scopes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"created_at": map[string]any{"type": "string", "format": "date-time"},
				"expires_at": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"TokenList": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tokens": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":           map[string]any{"type": "string"},
						"name":         map[string]any{"type": "string"},
						"scopes":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"created_at":   map[string]any{"type": "string", "format": "date-time"},
						"expires_at":   map[string]any{"type": "string", "format": "date-time"},
						"last_used_at": map[string]any{"type": "string", "format": "date-time"},
						"revoked":      map[string]any{"type": "boolean"},
					},
				}},
				"scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
		},
		"AuditPage": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"count": map[string]any{"type": "integer"},
				"events": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":         map[string]any{"type": "integer"},
						"org_id":     map[string]any{"type": "string"},
						"secret_id":  map[string]any{"type": "string"},
						"user_id":    map[string]any{"type": "string"},
						"event":      map[string]any{"type": "string"},
						"at":         map[string]any{"type": "string", "format": "date-time"},
						"ip":         map[string]any{"type": "string"},
						"user_agent": map[string]any{"type": "string"},
						"detail":     map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
					},
				}},
			},
		},
		"Instance": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"version":         map[string]any{"type": "string"},
				"crypto_version":  map[string]any{"type": "string"},
				"uptime_seconds":  map[string]any{"type": "integer"},
				"driver":          map[string]any{"type": "string"},
				"active_secrets":  map[string]any{"type": "integer"},
				"multi_org":       map[string]any{"type": "boolean"},
				"public_listener": map[string]any{"type": "boolean"},
			},
		},
		"SSOInfo": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"enabled":  map[string]any{"type": "boolean"},
				"required": map[string]any{"type": "boolean", "description": "Local credentials are refused."},
				"label":    map[string]any{"type": "string", "description": "What the button says."},
				"start_url": map[string]any{"type": "string",
					"description": "Where to send the browser: /auth/sso."},
			},
		},
		"WebhookEndpoint": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":         map[string]any{"type": "string"},
				"url":          map[string]any{"type": "string"},
				"events":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"max_attempts": map[string]any{"type": "integer", "description": "Including the first try."},
				"timeout":      map[string]any{"type": "string"},
				"disabled":     map[string]any{"type": "boolean"},
				"insecure": map[string]any{"type": "boolean",
					"description": "TLS verification is off for this endpoint."},
			},
		},
		"Webhooks": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"endpoints": map[string]any{
					"type": "array", "items": ref("WebhookEndpoint"),
				},
				"queue": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"pending":        map[string]any{"type": "integer"},
						"delivered":      map[string]any{"type": "integer"},
						"failed":         map[string]any{"type": "integer"},
						"oldest_pending": map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"signature": map[string]any{
					"type":        "object",
					"description": "How to verify a delivery, so a receiver can be written from this response.",
				},
			},
		},
		"Delivery": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":              map[string]any{"type": "string", "description": "Repeated in X-Peek-Delivery."},
				"endpoint":        map[string]any{"type": "string"},
				"event":           map[string]any{"type": "string"},
				"attempts":        map[string]any{"type": "integer"},
				"next_attempt_at": map[string]any{"type": "string", "format": "date-time"},
				"created_at":      map[string]any{"type": "string", "format": "date-time"},
				"delivered_at":    map[string]any{"type": "string", "format": "date-time"},
				"failed_at":       map[string]any{"type": "string", "format": "date-time"},
				"last_status":     map[string]any{"type": "integer"},
				"last_error":      map[string]any{"type": "string"},
			},
		},
		"Deliveries": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"deliveries": map[string]any{"type": "array", "items": ref("Delivery")},
			},
		},
	}
}

func toAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// handleOpenAPI serves the document.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	doc, err := s.OpenAPI()
	if err != nil {
		// Unreachable once the coverage test passes, which is the point of
		// having it.
		s.log.Error("build the openapi document", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, doc)
}
