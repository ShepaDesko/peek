package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

const hookSecret = "a-secret-long-enough-to-pass"

// TestWebhookSurfaceIsReadOnlyAndInternal is the point of the design: an
// operator can see everything and poke the queue, and nobody can add an
// endpoint over HTTP. A URL the API could set would make this server fetch on
// a caller's behalf, from inside the network the caller cannot reach.
func TestWebhookEndpointsAreVisibleButNotCreatable(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.Webhooks = []config.Webhook{{
			Name: "siem", URL: "https://receiver.example.test/hook",
			Secret: hookSecret, Events: []string{store.EventRevealed},
		}}
	})
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/webhooks", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /webhooks returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	endpoints, ok := body["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		t.Fatalf("endpoints = %v", body["endpoints"])
	}
	first, _ := endpoints[0].(map[string]any)
	if first["name"] != "siem" {
		t.Errorf("endpoint = %v", first)
	}
	// The HMAC key is a credential: it must not come back out of the API.
	if raw := rec.Body.String(); strings.Contains(raw, hookSecret) {
		t.Error("the response repeats the webhook secret")
	}
	if body["queue"] == nil || body["signature"] == nil {
		t.Error("the response does not describe the queue and the signature")
	}

	// There is no creation route: a POST to the collection is not allowed.
	if rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/webhooks", []byte(`{}`), nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /webhooks returned %d, want 405: endpoints live in peek.toml", rec.Code)
	}

	// And none of it is on the recipient-facing listener.
	for _, path := range []string{"/api/v1/webhooks", "/api/v1/webhooks/deliveries"} {
		if rec := do(t, h.public, http.MethodGet, path, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s on the public listener returned %d", path, rec.Code)
		}
	}
}

func TestWebhookQueueShowsWhatIsOwed(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.Webhooks = []config.Webhook{{
			Name: "siem", URL: "https://receiver.example.test/hook",
			Secret: hookSecret, Events: []string{store.EventRevealed},
		}}
	})
	admin := h.signIn(t)

	// Create and reveal a secret: the reveal is the subscribed event.
	c := newClient(t, "", "le mot de passe du routeur")
	h.create(t, c, nil)
	if rec := h.reveal(t, h.internal, c, c.keys.ReadToken); rec.Code != http.StatusOK {
		t.Fatalf("reveal returned %d: %s", rec.Code, rec.Body.String())
	}

	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/webhooks/deliveries?state=pending", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deliveries returned %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Deliveries []store.Delivery `json:"deliveries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Deliveries) != 1 {
		t.Fatalf("queued %d deliveries after a reveal, want 1", len(out.Deliveries))
	}
	got := out.Deliveries[0]
	if got.Event != store.EventRevealed || got.Endpoint != "siem" {
		t.Errorf("delivery = %+v", got)
	}
	if got.Payload != "" {
		t.Error("the listing returns the signed body; it belongs to the receiver")
	}

	// A bad state is refused rather than silently ignored.
	if rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/webhooks/deliveries?state=nonsense", nil, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown state returned %d", rec.Code)
	}
}

func TestWebhookTestSendsOnePing(t *testing.T) {
	var got struct {
		event string
		sig   string
	}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.event = r.Header.Get("X-Peek-Event")
		got.sig = r.Header.Get("X-Peek-Signature")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	h := newHarness(t, func(cfg *config.Config) {
		cfg.Webhooks = []config.Webhook{{Name: "siem", URL: receiver.URL, Secret: hookSecret}}
	})
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/webhooks/siem/test", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("test returned %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["ok"] != true {
		t.Fatalf("the ping failed: %v", body)
	}
	if got.event != "peek.ping" {
		t.Errorf("the receiver saw event %q", got.event)
	}
	if !strings.HasPrefix(got.sig, "v1=") {
		t.Errorf("the ping was not signed: %q", got.sig)
	}

	// An unknown endpoint answers 200 with ok:false — the call worked, the
	// delivery did not, and the distinction matters to whoever is debugging.
	rec = admin.do(t, h.internal, http.MethodPost, "/api/v1/webhooks/nope/test", nil, nil)
	if rec.Code != http.StatusOK || decodeBody(t, rec)["ok"] != false {
		t.Errorf("pinging an unknown endpoint: %d %s", rec.Code, rec.Body.String())
	}
}

// TestWebhookPokingNeedsASession: reading the queue is monitoring, which a
// token may do. Making the server call out is an administrator at a keyboard.
func TestWebhookPokingNeedsASession(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.Webhooks = []config.Webhook{{
			Name: "siem", URL: "https://receiver.example.test/hook", Secret: hookSecret,
		}}
	})
	token, _ := h.issueToken(t, []string{store.ScopeInstanceRead})
	bearer := map[string]string{"Authorization": "Bearer " + token}

	if rec := do(t, h.internal, http.MethodGet, "/api/v1/webhooks", nil, bearer); rec.Code != http.StatusOK {
		t.Errorf("a token with instance:read could not read the queue: %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/api/v1/webhooks/siem/test", "/api/v1/webhooks/retry"} {
		rec := do(t, h.internal, http.MethodPost, path, []byte(`{}`), bearer)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a token returned %d, want 403", path, rec.Code)
		}
	}
}

func TestWebhookRetryRequeuesFailures(t *testing.T) {
	h := newHarness(t, func(cfg *config.Config) {
		cfg.Webhooks = []config.Webhook{{
			Name: "siem", URL: "https://receiver.example.test/hook", Secret: hookSecret,
		}}
	})
	admin := h.signIn(t)

	id, err := h.store.EnqueueDelivery(t.Context(), store.Delivery{
		Endpoint: "siem", Event: store.EventRevealed, Payload: `{"event":"secret.revealed"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.DeliveryFailed(t.Context(), id, 500, "boom", time.Time{}, time.Now()); err != nil {
		t.Fatal(err)
	}

	rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/webhooks/retry", []byte(`{}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("retry returned %d: %s", rec.Code, rec.Body.String())
	}
	if n, _ := decodeBody(t, rec)["requeued"].(float64); n != 1 {
		t.Errorf("requeued = %v, want 1", decodeBody(t, rec)["requeued"])
	}
	rows, err := h.store.ListDeliveries(t.Context(), store.DeliveryFilter{State: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Attempts != 0 {
		t.Errorf("the row was not reset: %+v", rows)
	}

	// A delivery that does not exist is a 404, not a cheerful zero.
	if rec := admin.do(t, h.internal, http.MethodPost, "/api/v1/webhooks/retry",
		[]byte(`{"id":"does-not-exist"}`), nil); rec.Code != http.StatusNotFound {
		t.Errorf("retrying an unknown delivery returned %d", rec.Code)
	}
}

// TestNoWebhookNoQueue: an instance with nothing configured answers plainly
// rather than pretending the feature is half there.
func TestNoWebhookConfigured(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.signIn(t)

	rec := admin.do(t, h.internal, http.MethodGet, "/api/v1/webhooks", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /webhooks returned %d", rec.Code)
	}
	if endpoints, _ := decodeBody(t, rec)["endpoints"].([]any); len(endpoints) != 0 {
		t.Errorf("endpoints = %v", endpoints)
	}
	rec = admin.do(t, h.internal, http.MethodPost, "/api/v1/webhooks/siem/test", nil, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("testing with nothing configured returned %d, want 409", rec.Code)
	}
}
