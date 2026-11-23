package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/server"
	"github.com/ShepaDesko/peek/internal/storage"
	"github.com/ShepaDesko/peek/internal/store"
)

// harness is a server wired to an in-memory database, with both handlers.
type harness struct {
	srv      *server.Server
	internal http.Handler
	public   http.Handler
	cfg      *config.Config
	blobs    *storage.Local
	store    *store.Store
}

func newHarness(t *testing.T, tweak func(*config.Config)) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.PublicURL = "https://secrets.example.test"
	cfg.Security.AnonymousCreate = true
	cfg.Policy.MaxTTL = config.Days(7)
	cfg.Policy.DefaultTTL = config.Days(1)
	if tweak != nil {
		tweak(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test configuration invalid: %v", err)
	}

	st, err := store.OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	cipher, err := pcrypto.NewServerCipher(master)
	if err != nil {
		t.Fatal(err)
	}

	// Every harness gets real file storage in a temporary directory: the file
	// paths are part of the behaviour under test, and a nil backend would
	// make them silently refuse instead.
	blobs, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	srv, err := server.New(server.Options{
		Config:  &cfg,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Store:   st,
		Version: "test",
		Cipher:  cipher,
		Blobs:   blobs,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return &harness{
		srv:      srv,
		internal: srv.Handler("internal"),
		public:   srv.Handler("public"),
		cfg:      &cfg,
		blobs:    blobs,
		store:    st,
	}
}

// client is what the browser does, in Go: seal locally, send ciphertext.
type client struct {
	id           string
	contentKey   []byte
	kdf          pcrypto.KDFParams
	keys         pcrypto.Keys
	receiptToken []byte
	plaintext    string
}

func newClient(t *testing.T, passphrase, plaintext string) *client {
	t.Helper()
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	kdf, err := pcrypto.DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	// Cheap parameters keep the tests fast; the format is identical.
	kdf.MemoryKiB, kdf.Iterations = 8192, 1
	keys, err := pcrypto.DeriveKeys(key, passphrase, kdf)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	return &client{id: id, contentKey: key, kdf: kdf, keys: keys, receiptToken: receipt, plaintext: plaintext}
}

func (c *client) createBody(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	payload, err := pcrypto.Payload{Kind: pcrypto.KindText, Text: c.plaintext}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pcrypto.Seal(c.keys.Enc, pcrypto.AAD(c.id), payload)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"id":                 c.id,
		"kind":               "text",
		"ciphertext":         pcrypto.B64.EncodeToString(sealed),
		"read_token_hash":    pcrypto.B64.EncodeToString(c.keys.ReadTokenHash),
		"receipt_token_hash": pcrypto.B64.EncodeToString(pcrypto.HashReadToken(c.receiptToken)),
		"kdf": map[string]any{
			"salt":        pcrypto.B64.EncodeToString(c.kdf.Salt),
			"memory_kib":  c.kdf.MemoryKiB,
			"iterations":  c.kdf.Iterations,
			"parallelism": c.kdf.Parallelism,
		},
		"has_passphrase":         false,
		"ttl_seconds":            3600,
		"views":                  1,
		"retrieval_step":         true,
		"deletable_by_recipient": false,
	}
	if mutate != nil {
		mutate(body)
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func do(t *testing.T, h http.Handler, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return out
}

// create posts a secret and returns the response body.
func (h *harness) create(t *testing.T, c *client, mutate func(map[string]any)) map[string]any {
	t.Helper()
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, mutate), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}
	return decodeBody(t, rec)
}

func (h *harness) reveal(t *testing.T, handler http.Handler, c *client, token []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"read_token": pcrypto.B64.EncodeToString(token)})
	if err != nil {
		t.Fatal(err)
	}
	return do(t, handler, http.MethodPost, "/api/v1/secrets/"+c.id+"/reveal", body, nil)
}

// TestCreateRevealThenGone is the core journey: create, reveal once, and the
// second attempt must be indistinguishable from a link that never existed.
func TestCreateRevealThenGone(t *testing.T) {
	h := newHarness(t, nil)
	c := newClient(t, "", "mot de passe du compte X")
	created := h.create(t, c, nil)

	if created["url"] != "https://secrets.example.test/s/"+c.id {
		t.Fatalf("unexpected URL: %v", created["url"])
	}

	rec := h.reveal(t, h.public, c, c.keys.ReadToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("reveal returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	sealed, err := pcrypto.B64.DecodeString(body["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := pcrypto.Open(c.keys.Enc, pcrypto.AAD(c.id), sealed)
	if err != nil {
		t.Fatalf("the server returned something the client cannot decrypt: %v", err)
	}
	payload, err := pcrypto.UnmarshalPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Text != c.plaintext {
		t.Fatalf("round trip mismatch: %q", payload.Text)
	}
	if body["destroyed"] != true {
		t.Fatal("a one-view secret was not destroyed on reveal")
	}

	// Second read, and the metadata endpoint, must both look like "never existed".
	if rec := h.reveal(t, h.public, c, c.keys.ReadToken); rec.Code != http.StatusNotFound {
		t.Fatalf("second reveal returned %d, want 404", rec.Code)
	}
	meta := do(t, h.public, http.MethodGet, "/api/v1/secrets/"+c.id, nil, nil)
	if meta.Code != http.StatusNotFound {
		t.Fatalf("metadata after reveal returned %d, want 404", meta.Code)
	}
	unknown := do(t, h.public, http.MethodGet, "/api/v1/secrets/"+mustID(t), nil, nil)
	if unknown.Body.String() != meta.Body.String() {
		t.Fatalf("a consumed secret and an unknown one answer differently:\n%s\n%s", meta.Body.String(), unknown.Body.String())
	}
}

// TestPreviewBotConsumesNothing is the retrieval-step guarantee: a link
// preview fetches pages, it does not POST, so no view is spent.
func TestPreviewBotConsumesNothing(t *testing.T) {
	h := newHarness(t, nil)
	c := newClient(t, "", "secret")
	h.create(t, c, nil)

	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Slackbot-LinkExpanding 1.0)",
		"Microsoft-Outlook-SafeLinks",
		"Mozilla/5.0 (Windows NT 10.0) SkypeUriPreview Preview/0.5",
	} {
		rec := do(t, h.public, http.MethodGet, "/api/v1/secrets/"+c.id, nil, map[string]string{"User-Agent": ua})
		if rec.Code != http.StatusOK {
			t.Fatalf("metadata for %s returned %d", ua, rec.Code)
		}
		body := decodeBody(t, rec)
		if body["views_remaining"].(float64) != 1 {
			t.Fatalf("%s consumed a view", ua)
		}
	}

	// The real recipient still gets the secret.
	if rec := h.reveal(t, h.public, c, c.keys.ReadToken); rec.Code != http.StatusOK {
		t.Fatalf("recipient reveal after bot visits returned %d", rec.Code)
	}
}

// TestWrongPassphraseCostsNoView checks the proof-of-possession path: a wrong
// passphrase is rejected before the view counter is touched, and the attempt
// budget is enforced.
func TestWrongPassphraseCostsNoView(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Security.MaxPassphraseTries = 3 })
	right := newClient(t, "correct-passphrase", "payload")
	h.create(t, right, func(body map[string]any) { body["has_passphrase"] = true })

	wrong, err := pcrypto.DeriveKeys(right.contentKey, "wrong-passphrase", right.kdf)
	if err != nil {
		t.Fatal(err)
	}

	rec := h.reveal(t, h.public, right, wrong.ReadToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong passphrase returned %d, want 403: %s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Error struct {
			Code         string `json:"code"`
			AttemptsLeft *int   `json:"attempts_left"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody.Error.Code != "bad_token" || errBody.Error.AttemptsLeft == nil || *errBody.Error.AttemptsLeft != 2 {
		t.Fatalf("unexpected error body: %s", rec.Body.String())
	}

	meta := decodeBody(t, do(t, h.public, http.MethodGet, "/api/v1/secrets/"+right.id, nil, nil))
	if meta["views_remaining"].(float64) != 1 {
		t.Fatal("a wrong passphrase consumed a view")
	}

	// The right passphrase still works after a failure.
	if rec := h.reveal(t, h.public, right, right.keys.ReadToken); rec.Code != http.StatusOK {
		t.Fatalf("correct passphrase after a failure returned %d", rec.Code)
	}
}

func TestTooManyAttemptsBurnsTheSecret(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Security.MaxPassphraseTries = 3 })
	c := newClient(t, "right", "payload")
	h.create(t, c, func(body map[string]any) { body["has_passphrase"] = true })

	wrong, err := pcrypto.DeriveKeys(c.contentKey, "nope", c.kdf)
	if err != nil {
		t.Fatal(err)
	}
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, h.reveal(t, h.public, c, wrong.ReadToken).Code)
	}
	if codes[0] != 403 || codes[1] != 403 || codes[2] != http.StatusGone {
		t.Fatalf("attempt codes = %v, want [403 403 410]", codes)
	}
	// Even the correct passphrase is now useless: the secret is gone.
	if rec := h.reveal(t, h.public, c, c.keys.ReadToken); rec.Code != http.StatusNotFound {
		t.Fatalf("reveal after burn returned %d, want 404", rec.Code)
	}
}

// TestPublicListenerHidesTheAdminSurface is the M4 acceptance criterion.
func TestPublicListenerHidesTheAdminSurface(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.PublicListen = "0.0.0.0:8081" })
	c := newClient(t, "", "secret")

	for _, probe := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, "/api/v1/secrets", c.createBody(t, nil)},
		{http.MethodGet, "/api/v1/audit", nil},
		{http.MethodGet, "/api/v1/policy", nil},
		{http.MethodGet, "/api/v1/instance", nil},
		{http.MethodGet, "/api/v1/secrets/" + c.id + "/receipt", nil},
		{http.MethodPost, "/api/v1/secrets/" + c.id + "/burn", nil},
	} {
		rec := do(t, h.public, probe.method, probe.path, probe.body, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s on the public listener returned %d, want 404", probe.method, probe.path, rec.Code)
		}
	}

	// And the same routes work on the internal listener.
	if rec := do(t, h.internal, http.MethodGet, "/api/v1/policy", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("policy on the internal listener returned %d", rec.Code)
	}
}

// TestRealClientIP is the other M4 criterion: forwarded headers are honoured
// only from a declared proxy, and ignored everywhere else.
func TestRealClientIP(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Server.TrustedProxies = []string{"10.1.0.0/16"}
	})

	cases := []struct {
		name    string
		peer    string
		headers map[string]string
		wantIP  string
		trusted bool
	}{
		{
			name:    "untrusted peer spoofing a header",
			peer:    "198.51.100.9:1234",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"},
			wantIP:  "198.51.100.9",
		},
		{
			name:    "trusted proxy forwarding one hop",
			peer:    "10.1.2.3:4567",
			headers: map[string]string{"X-Forwarded-For": "203.0.113.5"},
			wantIP:  "203.0.113.5",
			trusted: true,
		},
		{
			name:    "trusted proxy chain keeps the rightmost untrusted address",
			peer:    "10.1.2.3:4567",
			headers: map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.5, 10.1.9.9"},
			wantIP:  "203.0.113.5",
			trusted: true,
		},
		{
			name:    "RFC 7239 Forwarded header",
			peer:    "10.1.2.3:4567",
			headers: map[string]string{"Forwarded": `for=203.0.113.77;proto=https;host=secrets.example.test`},
			wantIP:  "203.0.113.77",
			trusted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ip", nil)
			req.RemoteAddr = tc.peer
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.internal.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			var body struct {
				ClientIP    string `json:"client_ip"`
				TrustedPeer bool   `json:"trusted_peer"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.ClientIP != tc.wantIP {
				t.Errorf("client_ip = %q, want %q", body.ClientIP, tc.wantIP)
			}
			if body.TrustedPeer != tc.trusted {
				t.Errorf("trusted_peer = %v, want %v", body.TrustedPeer, tc.trusted)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.TLS.HSTS = true
		c.Server.TrustedProxies = []string{"192.0.2.0/24"}
	})
	rec := do(t, h.internal, http.MethodGet, "/", nil, map[string]string{"X-Forwarded-Proto": "https"})

	want := map[string]string{
		"Referrer-Policy":            "no-referrer",
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Cross-Origin-Opener-Policy": "same-origin",
		"X-Robots-Tag":               "noindex, nofollow, noarchive",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP is missing %q: %s", directive, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows inline scripts: %s", csp)
	}
	// 'wasm-unsafe-eval' is deliberate (Argon2id runs as WebAssembly), but
	// plain 'unsafe-eval' must never appear.
	if strings.Contains(strings.ReplaceAll(csp, "'wasm-unsafe-eval'", ""), "unsafe-eval") {
		t.Errorf("CSP allows eval(): %s", csp)
	}
	if !strings.Contains(csp, "'wasm-unsafe-eval'") {
		t.Errorf("CSP blocks the Argon2id WebAssembly module: %s", csp)
	}
	if hsts := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=") {
		t.Errorf("HSTS header missing behind a trusted https proxy: %q", hsts)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("the application shell is cacheable: %q", cc)
	}
}

func TestSecretRoutesAreNeverCached(t *testing.T) {
	h := newHarness(t, nil)
	c := newClient(t, "", "secret")
	h.create(t, c, nil)
	rec := do(t, h.public, http.MethodGet, "/api/v1/secrets/"+c.id, nil, nil)
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestReceiptAndBurn(t *testing.T) {
	h := newHarness(t, nil)
	c := newClient(t, "", "secret")
	h.create(t, c, func(body map[string]any) { body["views"] = 3 })

	token := pcrypto.B64.EncodeToString(c.receiptToken)
	rec := do(t, h.internal, http.MethodGet, "/api/v1/secrets/"+c.id+"/receipt", nil,
		map[string]string{"X-Peek-Token": token})
	if rec.Code != http.StatusOK {
		t.Fatalf("receipt returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["status"] != "active" || body["views_max"].(float64) != 3 {
		t.Fatalf("unexpected receipt: %v", body)
	}

	// A wrong receipt token must not reveal anything or destroy anything.
	bad, err := pcrypto.NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	rec = do(t, h.internal, http.MethodPost, "/api/v1/secrets/"+c.id+"/burn", nil,
		map[string]string{"X-Peek-Token": pcrypto.B64.EncodeToString(bad)})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("burn with a wrong token returned %d, want 404", rec.Code)
	}

	rec = do(t, h.internal, http.MethodPost, "/api/v1/secrets/"+c.id+"/burn", nil,
		map[string]string{"X-Peek-Token": token})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("burn returned %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.reveal(t, h.public, c, c.keys.ReadToken); rec.Code != http.StatusNotFound {
		t.Fatalf("reveal after burn returned %d", rec.Code)
	}
	// The sender can still read what happened.
	rec = do(t, h.internal, http.MethodGet, "/api/v1/secrets/"+c.id+"/receipt", nil,
		map[string]string{"X-Peek-Token": token})
	if rec.Code != http.StatusOK || decodeBody(t, rec)["status"] != "burned" {
		t.Fatalf("receipt after burn: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyRefusals(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Policy.MaxViews = 5
		c.Policy.MaxTTL = config.Days(1)
		c.Policy.MaxSecretBytes = 1024
		c.Policy.RequirePassphrase = true
	})

	cases := []struct {
		name   string
		mutate func(map[string]any)
		field  string
	}{
		{"too many views", func(b map[string]any) { b["views"] = 50; b["has_passphrase"] = true }, "views"},
		{"too long", func(b map[string]any) { b["ttl_seconds"] = 60 * 60 * 24 * 10; b["has_passphrase"] = true }, "ttl"},
		{"passphrase required", func(b map[string]any) { b["has_passphrase"] = false }, "passphrase"},
		{"payload too large", func(b map[string]any) {
			b["has_passphrase"] = true
			b["ciphertext"] = pcrypto.B64.EncodeToString(bytes.Repeat([]byte{1}, 4096))
		}, "ciphertext"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, "pass", "x")
			rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, tc.mutate), nil)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422: %s", rec.Code, rec.Body.String())
			}
			var body apiErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Field != tc.field {
				t.Fatalf("field = %q, want %q (%s)", body.Error.Field, tc.field, body.Error.Message)
			}
		})
	}
}

type apiErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Field   string `json:"field"`
	} `json:"error"`
}

func TestCreationDisabledByDefault(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Security.AnonymousCreate = false })
	c := newClient(t, "", "x")
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 when anonymous creation is off and nobody is signed in", rec.Code)
	}

	// Signed in, the same request works and the secret is attributed.
	admin := h.signIn(t)
	rec = admin.do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d for a signed-in creator: %s", rec.Code, rec.Body.String())
	}
	dash := decodeBody(t, admin.do(t, h.internal, http.MethodGet, "/api/v1/dashboard/secrets", nil, nil))
	if len(dash["secrets"].([]any)) != 1 {
		t.Fatalf("the secret is not on the creator dashboard: %v", dash)
	}
}

func TestCreateCIDRGate(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Security.CreateAllowedCIDRs = []string{"10.0.0.0/8"}
	})
	c := newClient(t, "", "x")
	// The harness sends requests from 192.0.2.10.
	rec := do(t, h.internal, http.MethodPost, "/api/v1/secrets", c.createBody(t, nil), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 from a disallowed network", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(c.createBody(t, nil)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.4.5.6:1111"
	rec = httptest.NewRecorder()
	h.internal.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d from an allowed network: %s", rec.Code, rec.Body.String())
	}
}

func TestRateLimitOnReveal(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Security.RateRead = config.RateLimit{Burst: 3, Rate: 1, Window: config.Duration(time.Hour)}
	})
	c := newClient(t, "", "x")
	h.create(t, c, nil)

	statuses := map[int]int{}
	for i := 0; i < 6; i++ {
		rec := do(t, h.public, http.MethodGet, "/api/v1/secrets/"+c.id, nil, nil)
		statuses[rec.Code]++
	}
	if statuses[http.StatusTooManyRequests] == 0 {
		t.Fatalf("no request was rate limited: %v", statuses)
	}
	if statuses[http.StatusOK] > 3 {
		t.Fatalf("burst of 3 allowed %d requests", statuses[http.StatusOK])
	}
}

// TestConcurrentRevealOverHTTP is the end-to-end version of the single-view
// guarantee: fifty simultaneous HTTP reveals, exactly one 200.
func TestConcurrentRevealOverHTTP(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Security.RateRead = config.RateLimit{Burst: 0} // limiting off, concurrency is the subject
	})
	c := newClient(t, "", "only once")
	h.create(t, c, nil)

	const readers = 50
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		seen = map[int]int{}
	)
	start := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"read_token": pcrypto.B64.EncodeToString(c.keys.ReadToken)})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+c.id+"/reveal", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i%250+1)
			rec := httptest.NewRecorder()
			<-start
			h.public.ServeHTTP(rec, req)
			mu.Lock()
			seen[rec.Code]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if seen[http.StatusOK] != 1 {
		t.Fatalf("%d readers got the secret, want exactly 1 (statuses: %v)", seen[http.StatusOK], seen)
	}
}

func TestHealthAndReadyAndRobots(t *testing.T) {
	h := newHarness(t, nil)
	if rec := do(t, h.public, http.MethodGet, "/healthz", nil, nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("healthz: %d %q", rec.Code, rec.Body.String())
	}
	rec := do(t, h.public, http.MethodGet, "/readyz", nil, nil)
	if rec.Code != http.StatusOK || decodeBody(t, rec)["ready"] != true {
		t.Fatalf("readyz: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h.public, http.MethodGet, "/robots.txt", nil, nil); !strings.Contains(rec.Body.String(), "Disallow: /") {
		t.Fatalf("robots.txt: %q", rec.Body.String())
	}
}

func TestBrandingEndpoints(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Branding.ServiceName = "Coffre ACME"
		c.Branding.PrimaryColor = "#8b0000"
	})
	rec := do(t, h.public, http.MethodGet, "/api/v1/branding", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("branding: %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["service_name"] != "Coffre ACME" {
		t.Fatalf("service_name = %v", body["service_name"])
	}
	palette, ok := body["palette"].(map[string]any)
	if !ok || palette["primary"] != "#8b0000" {
		t.Fatalf("palette = %v", body["palette"])
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the branding endpoint")
	}
	again := do(t, h.public, http.MethodGet, "/api/v1/branding", nil, map[string]string{"If-None-Match": etag})
	if again.Code != http.StatusNotModified {
		t.Fatalf("conditional branding request returned %d, want 304", again.Code)
	}

	css := do(t, h.public, http.MethodGet, "/branding.css", nil, nil)
	if css.Code != http.StatusOK || !strings.Contains(css.Body.String(), "--peek-primary: #8b0000") {
		t.Fatalf("branding.css: %d %q", css.Code, css.Body.String())
	}
}

func TestAuditTrailRecordsWithoutSecretContent(t *testing.T) {
	h := newHarness(t, nil)
	c := newClient(t, "", "très secret")
	h.create(t, c, nil)
	do(t, h.public, http.MethodGet, "/api/v1/secrets/"+c.id, nil, nil)
	h.reveal(t, h.public, c, c.keys.ReadToken)

	anonymous := do(t, h.internal, http.MethodGet, "/api/v1/audit?secret_id="+c.id, nil, nil)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("the audit trail answered %d to an anonymous caller, want 401", anonymous.Code)
	}

	admin := h.signIn(t)
	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/audit?secret_id="+c.id, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit: %d", rec.Code)
	}
	raw := rec.Body.String()
	for _, forbidden := range []string{
		"très secret",
		pcrypto.B64.EncodeToString(c.contentKey),
		pcrypto.B64.EncodeToString(c.keys.ReadToken),
		pcrypto.B64.EncodeToString(c.receiptToken),
	} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("the audit trail leaked secret material: %q", forbidden)
		}
	}
	var body struct {
		Events []store.AuditEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range body.Events {
		got[e.Event] = true
	}
	for _, want := range []string{store.EventCreated, store.EventPageViewed, store.EventRevealed} {
		if !got[want] {
			t.Errorf("audit trail is missing %s (got %v)", want, got)
		}
	}
}

func TestMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	cases := []struct {
		name, method, path string
		body               []byte
		want               int
	}{
		{"malformed id", http.MethodGet, "/api/v1/secrets/not-an-id", nil, http.StatusNotFound},
		{"garbage json", http.MethodPost, "/api/v1/secrets", []byte("{"), http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/api/v1/secrets", []byte(`{"nope":1}`), http.StatusBadRequest},
		{"empty reveal", http.MethodPost, "/api/v1/secrets/" + mustID(t) + "/reveal", []byte(`{}`), http.StatusBadRequest},
		{"wrong method", http.MethodPut, "/api/v1/secrets", nil, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := do(t, h.internal, tc.method, tc.path, tc.body, nil); rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := pcrypto.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
