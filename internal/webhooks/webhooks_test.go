package webhooks_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
	"github.com/ShepaDesko/peek/internal/webhooks"
)

const testSecret = "a-secret-long-enough-to-pass"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.OpenMemory(context.Background())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newPair builds a dispatcher and a deliverer over one configuration, which is
// how they are used: the first writes the queue, the second drains it.
func newPair(t *testing.T, st *store.Store, hooks ...config.Webhook) (*webhooks.Dispatcher, *webhooks.Deliverer) {
	t.Helper()
	cfg := config.Default()
	cfg.PublicURL = "https://secrets.example.test"
	cfg.Webhooks = hooks
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test configuration invalid: %v", err)
	}
	sender, err := webhooks.NewDeliverer(&cfg, st, quiet(), "test")
	if err != nil {
		t.Fatalf("deliverer: %v", err)
	}
	return webhooks.NewDispatcher(&cfg, st, quiet()), sender
}

// --- signing ---------------------------------------------------------------

func TestSignatureCoversTheTimestamp(t *testing.T) {
	body := []byte(`{"event":"secret.revealed"}`)
	sig := webhooks.Sign(testSecret, 1700000000, body)

	if !webhooks.Verify(testSecret, sig, 1700000000, body) {
		t.Fatal("a signature does not verify against what it signed")
	}
	// A recorded delivery replayed with a fresh timestamp must not verify:
	// that is the whole reason the timestamp is inside the signed string and
	// not only in a header.
	if webhooks.Verify(testSecret, sig, 1700000001, body) {
		t.Error("the signature verified against a different timestamp")
	}
	if webhooks.Verify(testSecret, sig, 1700000000, []byte(`{"event":"secret.burned"}`)) {
		t.Error("the signature verified against a different body")
	}
	if webhooks.Verify("another-secret-long-enough", sig, 1700000000, body) {
		t.Error("the signature verified under the wrong key")
	}
	if got := sig[:3]; got != "v1=" {
		t.Errorf("signature is not version-prefixed: %q", sig)
	}
}

// TestSignatureIsNotLengthExtendable is the reason the timestamp and the body
// are joined by a separator rather than concatenated: without one, a receiver
// could be fooled by moving the boundary.
func TestSignatureSeparatesTheFields(t *testing.T) {
	a := webhooks.Sign(testSecret, 12, []byte("34.body"))
	b := webhooks.Sign(testSecret, 1234, []byte("body"))
	if a == b {
		t.Error("timestamp 12 with body \"34.body\" signs the same as 1234 with \"body\"")
	}
}

// --- what leaves the instance ----------------------------------------------

// TestPayloadFieldsAreFixed is the guard that makes forwarding safe by
// construction. A future audit detail cannot add a field to the body, because
// the body is built from this struct and nothing else.
func TestPayloadFieldsAreFixed(t *testing.T) {
	var got []string
	rt := reflect.TypeOf(webhooks.Payload{})
	for i := range rt.NumField() {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		got = append(got, name)
	}
	sort.Strings(got)

	want := []string{"at", "detail", "event", "id", "instance", "ip", "org", "secret_id", "user_agent", "user_id"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the webhook payload changed shape.\n got: %v\nwant: %v\n"+
			"Adding a field here means deciding, again, that it can never carry "+
			"a secret, a key or a URL fragment.", got, want)
	}
}

// TestDefaultEventsExist keeps the default subscription honest. config cannot
// import store (store reads config), so the two lists can only be checked
// against each other from a package that imports both.
func TestDefaultEventsExist(t *testing.T) {
	known := map[string]bool{
		store.EventRevealed:         true,
		store.EventExpired:          true,
		store.EventBurned:           true,
		store.EventRequestDeposited: true,
		store.EventCreated:          true,
		store.EventDeleted:          true,
		store.EventFileDownloaded:   true,
	}
	for _, event := range config.DefaultWebhookEvents {
		if !known[event] {
			t.Errorf("default subscription names %q, which is not an audit event name", event)
		}
	}
}

// --- queueing --------------------------------------------------------------

func TestDispatcherQueuesOnlySubscribedEvents(t *testing.T) {
	st := newStore(t)
	dispatcher, _ := newPair(t, st, config.Webhook{
		Name:   "siem",
		URL:    "https://receiver.example.test/hook",
		Secret: testSecret,
		Events: []string{store.EventRevealed},
	})

	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})
	dispatcher.Forward(store.AuditEvent{Event: store.EventCreated, SecretID: "def", At: time.Now()})
	dispatcher.Forward(store.AuditEvent{Event: store.EventLogin, UserID: "u1", At: time.Now()})

	rows, err := st.ListDeliveries(context.Background(), store.DeliveryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("queued %d deliveries, want 1 (only secret.revealed is subscribed)", len(rows))
	}
	if rows[0].Event != store.EventRevealed || rows[0].Endpoint != "siem" {
		t.Errorf("queued the wrong thing: %+v", rows[0])
	}
}

func TestDispatcherQueuesOnePerEndpoint(t *testing.T) {
	st := newStore(t)
	dispatcher, _ := newPair(t, st,
		config.Webhook{Name: "siem", URL: "https://a.example.test/h", Secret: testSecret, Events: []string{"*"}},
		config.Webhook{Name: "chat", URL: "https://b.example.test/h", Secret: testSecret, Events: []string{store.EventRevealed}},
		config.Webhook{Name: "off", URL: "https://c.example.test/h", Secret: testSecret, Events: []string{"*"}, Disabled: true},
	)

	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})

	rows, err := st.ListDeliveries(context.Background(), store.DeliveryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.Endpoint)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"chat", "siem"}) {
		t.Errorf("queued for %v, want chat and siem (off is disabled)", names)
	}
}

// --- delivery --------------------------------------------------------------

type capture struct {
	calls   atomic.Int32
	status  atomic.Int32
	lastSig atomic.Value
	lastTS  atomic.Int64
	lastID  atomic.Value
	body    atomic.Value
}

func (c *capture) handler(w http.ResponseWriter, r *http.Request) {
	c.calls.Add(1)
	body, _ := io.ReadAll(r.Body)
	c.body.Store(body)
	c.lastSig.Store(r.Header.Get(webhooks.HeaderSignature))
	c.lastID.Store(r.Header.Get(webhooks.HeaderDelivery))
	ts, _ := strconv.ParseInt(r.Header.Get(webhooks.HeaderTimestamp), 10, 64)
	c.lastTS.Store(ts)
	w.WriteHeader(int(c.status.Load()))
}

func newReceiver(status int) (*httptest.Server, *capture) {
	c := &capture{}
	c.status.Store(int32(status)) //nolint:gosec // a test status code
	return httptest.NewServer(http.HandlerFunc(c.handler)), c
}

func TestDeliveryIsSignedAndRecorded(t *testing.T) {
	st := newStore(t)
	receiver, rec := newReceiver(http.StatusNoContent)
	defer receiver.Close()

	dispatcher, sender := newPair(t, st, config.Webhook{
		Name: "siem", URL: receiver.URL, Secret: testSecret, Events: []string{store.EventRevealed},
	})
	dispatcher.Forward(store.AuditEvent{
		Event: store.EventRevealed, SecretID: "abc", OrgID: "default",
		IP: "203.0.113.4", UserAgent: "curl/8", At: time.Now(),
	})

	sent, retried, failed := sender.Drain(context.Background(), time.Now())
	if sent != 1 || retried != 0 || failed != 0 {
		t.Fatalf("drain reported sent=%d retried=%d failed=%d", sent, retried, failed)
	}
	if rec.calls.Load() != 1 {
		t.Fatalf("the receiver was called %d times", rec.calls.Load())
	}

	body, _ := rec.body.Load().([]byte)
	sig, _ := rec.lastSig.Load().(string)
	if !webhooks.Verify(testSecret, sig, rec.lastTS.Load(), body) {
		t.Error("the signature the receiver got does not verify over the body it got")
	}

	var payload webhooks.Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("the body is not the documented payload: %v", err)
	}
	if payload.Event != store.EventRevealed || payload.SecretID != "abc" {
		t.Errorf("payload = %+v", payload)
	}
	if id, _ := rec.lastID.Load().(string); id != payload.ID {
		t.Errorf("X-Peek-Delivery %q does not match the payload id %q", id, payload.ID)
	}
	if payload.Instance != "https://secrets.example.test" {
		t.Errorf("the payload does not name the instance: %q", payload.Instance)
	}

	rows, err := st.ListDeliveries(context.Background(), store.DeliveryFilter{State: "delivered"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Attempts != 1 || rows[0].LastStatus != http.StatusNoContent {
		t.Errorf("the row was not closed out as delivered: %+v", rows)
	}
}

func TestServerErrorIsRetriedWithBackoff(t *testing.T) {
	st := newStore(t)
	receiver, rec := newReceiver(http.StatusBadGateway)
	defer receiver.Close()

	dispatcher, sender := newPair(t, st, config.Webhook{
		Name: "siem", URL: receiver.URL, Secret: testSecret,
		Events: []string{store.EventRevealed}, MaxAttempts: 3,
	})
	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})

	now := time.Now()
	if sent, retried, failed := sender.Drain(context.Background(), now); sent != 0 || retried != 1 || failed != 0 {
		t.Fatalf("first attempt: sent=%d retried=%d failed=%d", sent, retried, failed)
	}
	// Still pending, and not due again yet: a receiver that is down must not
	// be hammered once per tick.
	if _, _, _ = sender.Drain(context.Background(), now); rec.calls.Load() != 1 {
		t.Fatalf("the receiver was called %d times; the backoff did not hold", rec.calls.Load())
	}

	// Second attempt after the first wait, third after the second, then it
	// gives up: three attempts is the configured budget.
	now = now.Add(config.WebhookBackoff(1) + time.Second)
	if _, retried, _ := sender.Drain(context.Background(), now); retried != 1 {
		t.Error("the second attempt did not happen when it came due")
	}
	now = now.Add(config.WebhookBackoff(2) + time.Second)
	if _, _, failed := sender.Drain(context.Background(), now); failed != 1 {
		t.Error("the third attempt did not exhaust the budget")
	}
	if rec.calls.Load() != 3 {
		t.Errorf("the receiver was called %d times, want 3", rec.calls.Load())
	}

	rows, err := st.ListDeliveries(context.Background(), store.DeliveryFilter{State: "failed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the exhausted delivery is not marked failed: %+v", rows)
	}
	if rows[0].LastStatus != http.StatusBadGateway || rows[0].LastError == "" {
		t.Errorf("the row does not say what happened: %+v", rows[0])
	}
	// And the operator can send it again once the receiver is fixed.
	rec.status.Store(http.StatusOK)
	n, err := st.RetryFailedDeliveries(context.Background(), "", now)
	if err != nil || n != 1 {
		t.Fatalf("retry requeued %d rows (err %v)", n, err)
	}
	if sent, _, _ := sender.Drain(context.Background(), now); sent != 1 {
		t.Error("the requeued delivery did not go out")
	}
}

func TestClientErrorIsPermanent(t *testing.T) {
	st := newStore(t)
	receiver, rec := newReceiver(http.StatusBadRequest)
	defer receiver.Close()

	dispatcher, sender := newPair(t, st, config.Webhook{
		Name: "siem", URL: receiver.URL, Secret: testSecret,
		Events: []string{store.EventRevealed}, MaxAttempts: 6,
	})
	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})

	if _, _, failed := sender.Drain(context.Background(), time.Now()); failed != 1 {
		t.Fatal("a 400 was queued for retry; the receiver understood and refused")
	}
	if rec.calls.Load() != 1 {
		t.Errorf("the receiver was called %d times for a permanent refusal", rec.calls.Load())
	}
}

func TestRateLimitIsRetried(t *testing.T) {
	st := newStore(t)
	receiver, _ := newReceiver(http.StatusTooManyRequests)
	defer receiver.Close()

	dispatcher, sender := newPair(t, st, config.Webhook{
		Name: "siem", URL: receiver.URL, Secret: testSecret,
		Events: []string{store.EventRevealed}, MaxAttempts: 4,
	})
	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})

	if _, retried, _ := sender.Drain(context.Background(), time.Now()); retried != 1 {
		t.Error("429 was treated as permanent; it is the receiver asking us to slow down")
	}
}

// TestRedirectIsRefused: a redirect would send the signed body, headers and
// all, to a host the operator never configured.
func TestRedirectIsRefused(t *testing.T) {
	st := newStore(t)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	dispatcher, sender := newPair(t, st, config.Webhook{
		Name: "siem", URL: redirector.URL, Secret: testSecret,
		Events: []string{store.EventRevealed}, MaxAttempts: 1,
	})
	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})

	if _, _, failed := sender.Drain(context.Background(), time.Now()); failed != 1 {
		t.Error("the delivery followed a redirect instead of refusing it")
	}
}

func TestUnreachableReceiverNeverLogsTheURL(t *testing.T) {
	st := newStore(t)
	// A URL with a credential in the query string, which several receivers do,
	// pointed at a port nothing listens on.
	dispatcher, sender := newPair(t, st, config.Webhook{
		Name:   "siem",
		URL:    "http://127.0.0.1:1/hook?token=super-secret-value",
		Secret: testSecret, Events: []string{store.EventRevealed}, MaxAttempts: 1,
	})
	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})
	sender.Drain(context.Background(), time.Now())

	rows, err := st.ListDeliveries(context.Background(), store.DeliveryFilter{State: "failed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one failed row, got %+v", rows)
	}
	if strings.Contains(rows[0].LastError, "super-secret-value") || strings.Contains(rows[0].LastError, "/hook") {
		t.Errorf("the recorded error repeats the webhook URL: %q", rows[0].LastError)
	}
	if rows[0].LastError == "" {
		t.Error("the recorded error says nothing at all")
	}
}

// TestDeliveryToARemovedEndpointFails: the configuration changed while events
// were queued. Dropping them silently would be worse than saying so.
func TestDeliveryToARemovedEndpointFails(t *testing.T) {
	st := newStore(t)
	dispatcher, _ := newPair(t, st, config.Webhook{
		Name: "siem", URL: "https://a.example.test/h", Secret: testSecret, Events: []string{"*"},
	})
	dispatcher.Forward(store.AuditEvent{Event: store.EventRevealed, SecretID: "abc", At: time.Now()})

	// Restart with the endpoint gone.
	_, sender := newPair(t, st, config.Webhook{
		Name: "other", URL: "https://b.example.test/h", Secret: testSecret, Events: []string{"*"},
	})
	if _, _, failed := sender.Drain(context.Background(), time.Now()); failed != 1 {
		t.Fatal("a delivery for a vanished endpoint was not closed out")
	}
	rows, _ := st.ListDeliveries(context.Background(), store.DeliveryFilter{State: "failed"})
	if len(rows) != 1 || !strings.Contains(rows[0].LastError, "no longer configured") {
		t.Errorf("the row does not explain itself: %+v", rows)
	}
}

func TestPingProvesThePath(t *testing.T) {
	st := newStore(t)
	receiver, rec := newReceiver(http.StatusOK)
	defer receiver.Close()

	_, sender := newPair(t, st, config.Webhook{
		Name: "siem", URL: receiver.URL, Secret: testSecret,
	})
	status, err := sender.Ping(context.Background(), "siem")
	if err != nil || status != http.StatusOK {
		t.Fatalf("ping: status %d, err %v", status, err)
	}
	body, _ := rec.body.Load().([]byte)
	var payload webhooks.Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Event != webhooks.PingEvent {
		t.Errorf("the ping is not labelled as one: %q", payload.Event)
	}
	// A ping is not an audit event, so it leaves nothing in the queue.
	rows, _ := st.ListDeliveries(context.Background(), store.DeliveryFilter{})
	if len(rows) != 0 {
		t.Errorf("the ping was queued: %+v", rows)
	}
	if _, err := sender.Ping(context.Background(), "nope"); err == nil {
		t.Error("pinging an endpoint that does not exist succeeded")
	}
}

// TestQueueIsDrainedOncePerCluster is the single-delivery guarantee at the
// store level: two nodes reading the queue must not both send the same row.
// The job lock is what prevents it in production; this checks the lock itself
// does what the drain relies on.
func TestJobLockSerialisesTheDrain(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	now := time.Now()

	first, err := st.TryLock(ctx, "webhooks", "node-a", 2*time.Minute, now)
	if err != nil || !first {
		t.Fatalf("the first node could not claim the drain: %v %v", first, err)
	}
	second, err := st.TryLock(ctx, "webhooks", "node-b", 2*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Error("two nodes claimed the drain at once: every delivery would be sent twice")
	}
	// And an expired lease is stolen, so a node that died mid-drain does not
	// stop the queue for ever.
	stolen, err := st.TryLock(ctx, "webhooks", "node-b", time.Minute, now.Add(3*time.Minute))
	if err != nil || !stolen {
		t.Errorf("an expired lease was not stolen: %v %v", stolen, err)
	}
}

func TestPurgeKeepsFailuresLonger(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	now := time.Now()

	delivered, err := st.EnqueueDelivery(ctx, store.Delivery{Endpoint: "siem", Event: "e", Payload: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := st.EnqueueDelivery(ctx, store.Delivery{Endpoint: "siem", Event: "e", Payload: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	old := now.Add(-10 * 24 * time.Hour)
	if err := st.DeliverySucceeded(ctx, delivered, 200, old); err != nil {
		t.Fatal(err)
	}
	if err := st.DeliveryFailed(ctx, failed, 500, "boom", time.Time{}, old); err != nil {
		t.Fatal(err)
	}

	n, err := st.PurgeDeliveries(ctx, 7*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purged %d rows, want 1: a failure is what an operator comes looking for", n)
	}
	rows, _ := st.ListDeliveries(ctx, store.DeliveryFilter{})
	if len(rows) != 1 || rows[0].ID != failed {
		t.Errorf("the wrong row survived: %+v", rows)
	}
}
