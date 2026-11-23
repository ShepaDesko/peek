// Package webhooks delivers audit events to the endpoints an operator
// configured, signed, with retries, exactly once per cluster.
//
// Three decisions shape the whole package.
//
// Endpoints come from peek.toml and nowhere else. A URL a user could choose
// would make the server fetch on their behalf — the classic request-forgery
// hole, pointed at the operator's own network from inside it. There is no API
// to add one, on purpose.
//
// The body is an audit event. That trail is already built never to contain a
// secret, a key, a passphrase or a URL fragment, so forwarding it is safe by
// construction rather than by review. It does carry identifiers and sometimes
// an e-mail address, which is why the documentation says to point a webhook
// somewhere you would be happy to see the audit trail.
//
// Nothing is sent from a request. The handler writes a row; the background job
// delivers it. A receiver that hangs cannot slow a reveal down, a restart
// mid-retry loses nothing, and the job lock means a three-node cluster sends
// one copy rather than three.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/store"
)

// Header names. They are part of the contract with every receiver, so they are
// constants rather than literals scattered through the file.
const (
	HeaderEvent     = "X-Peek-Event"
	HeaderDelivery  = "X-Peek-Delivery"
	HeaderTimestamp = "X-Peek-Timestamp"
	HeaderSignature = "X-Peek-Signature"
	HeaderAttempt   = "X-Peek-Attempt"
)

// SignatureVersion prefixes the signature so the scheme can change later
// without a receiver guessing which one it is looking at.
const SignatureVersion = "v1"

// PingEvent is what peek webhook test sends. It is not an audit event: it
// exists so an operator can prove the path works before a real secret does.
const PingEvent = "peek.ping"

// DefaultTimeout bounds one attempt. Long enough for a slow receiver on a
// congested link, short enough that a hung one does not hold the drain.
const DefaultTimeout = 10 * time.Second

// defaultQueueRetention is how long a finished delivery is kept for the
// operator to look at. Failed ones are kept twice as long by the store.
const defaultQueueRetention = 7 * 24 * time.Hour

// Payload is the JSON body of a delivery. The field set is fixed and small:
// anything that is not in this struct cannot leave the instance through a
// webhook, whatever a future audit detail happens to contain.
type Payload struct {
	// ID is the delivery identifier, repeated in the X-Peek-Delivery header.
	// A receiver can use it to make its own handling idempotent, which is the
	// honest answer to "is delivery exactly once?" — it is at least once.
	ID       string            `json:"id"`
	Event    string            `json:"event"`
	At       time.Time         `json:"at"`
	Instance string            `json:"instance"`
	Org      string            `json:"org"`
	SecretID string            `json:"secret_id,omitempty"`
	UserID   string            `json:"user_id,omitempty"`
	IP       string            `json:"ip,omitempty"`
	Agent    string            `json:"user_agent,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
}

// Sign returns the value of the X-Peek-Signature header.
//
// The timestamp is inside the signed string, not only in a header, so a
// recorded delivery cannot be replayed later with a fresh timestamp. A
// receiver should refuse a timestamp that is more than a few minutes old.
func Sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return SignatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header in constant time. Receivers written in Go
// can import this; the documentation shows the same thing in a shell and in
// Python for everyone else.
func Verify(secret, header string, timestamp int64, body []byte) bool {
	want := Sign(secret, timestamp, body)
	return subtle.ConstantTimeCompare([]byte(header), []byte(want)) == 1
}

// Dispatcher turns audit events into queued deliveries. It satisfies
// audit.Forwarder, which is how it hooks into the one place that writes the
// trail.
type Dispatcher struct {
	endpoints []config.Webhook
	instance  string
	store     *store.Store
	log       *slog.Logger
}

// NewDispatcher builds one. Endpoints marked disabled are dropped here, so
// nothing further down has to remember to check.
func NewDispatcher(cfg *config.Config, st *store.Store, log *slog.Logger) *Dispatcher {
	var live []config.Webhook
	for _, hook := range cfg.Webhooks {
		if !hook.Disabled {
			live = append(live, hook)
		}
	}
	return &Dispatcher{endpoints: live, instance: cfg.PublicURL, store: st, log: log}
}

// Enabled reports whether any endpoint is live.
func (d *Dispatcher) Enabled() bool { return d != nil && len(d.endpoints) > 0 }

// Endpoints returns the live endpoints, for the CLI and the admin page.
func (d *Dispatcher) Endpoints() []config.Webhook {
	if d == nil {
		return nil
	}
	out := make([]config.Webhook, len(d.endpoints))
	copy(out, d.endpoints)
	return out
}

// Describe returns one line for the startup log.
func (d *Dispatcher) Describe() string {
	if !d.Enabled() {
		return "none"
	}
	names := make([]string, 0, len(d.endpoints))
	for _, hook := range d.endpoints {
		names = append(names, hook.Name)
	}
	return strings.Join(names, ", ")
}

// Forward queues the event for every endpoint subscribed to it.
//
// It does not use the request's context. The response has often been written
// by the time this runs, and a cancelled context would drop the row — which
// is exactly the event an operator is watching for.
func (d *Dispatcher) Forward(event store.AuditEvent) {
	if !d.Enabled() || d.store == nil {
		return
	}
	var subscribed []config.Webhook
	for _, hook := range d.endpoints {
		if hook.Subscribed(event.Event) {
			subscribed = append(subscribed, hook)
		}
	}
	if len(subscribed) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, hook := range subscribed {
		if err := d.enqueue(ctx, hook.Name, event); err != nil {
			// The database copy of the event is already written: a queue
			// failure loses the notification, not the record.
			d.log.Error("cannot queue webhook delivery",
				"endpoint", hook.Name, "event", event.Event, "error", err.Error())
		}
	}
}

func (d *Dispatcher) enqueue(ctx context.Context, endpoint string, event store.AuditEvent) error {
	id, err := store.NewID()
	if err != nil {
		return err
	}
	at := event.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	body, err := json.Marshal(Payload{
		ID:       id,
		Event:    event.Event,
		At:       at.UTC(),
		Instance: d.instance,
		Org:      event.OrgID,
		SecretID: event.SecretID,
		UserID:   event.UserID,
		IP:       event.IP,
		Agent:    event.UserAgent,
		Detail:   event.Detail,
	})
	if err != nil {
		return err
	}
	_, err = d.store.EnqueueDelivery(ctx, store.Delivery{
		ID:       id,
		OrgID:    event.OrgID,
		Endpoint: endpoint,
		Event:    event.Event,
		Payload:  string(body),
	})
	return err
}

// Close satisfies audit.Forwarder. There is nothing to flush: the queue is in
// the database, and the job drains it.
func (d *Dispatcher) Close() error { return nil }

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

// Deliverer drains the queue. The jobs runner owns one and calls Drain on a
// ticker, under the cluster-wide job lock.
type Deliverer struct {
	byName   map[string]config.Webhook
	clients  map[string]*http.Client
	store    *store.Store
	log      *slog.Logger
	agent    string
	instance string
}

// NewDeliverer builds the sender. A broken ca_file is fatal: an operator who
// pinned an authority meant it, and falling back to the system pool would be a
// silent downgrade.
func NewDeliverer(cfg *config.Config, st *store.Store, log *slog.Logger, version string) (*Deliverer, error) {
	d := &Deliverer{
		byName:   map[string]config.Webhook{},
		clients:  map[string]*http.Client{},
		store:    st,
		log:      log,
		agent:    "Peek/" + version + " (+webhook)",
		instance: cfg.PublicURL,
	}
	for _, hook := range cfg.Webhooks {
		if hook.Disabled {
			continue
		}
		client, err := newClient(hook)
		if err != nil {
			return nil, fmt.Errorf("webhook %s: %w", hook.Name, err)
		}
		d.byName[hook.Name] = hook
		d.clients[hook.Name] = client
	}
	return d, nil
}

// Enabled reports whether there is anything to deliver to.
func (d *Deliverer) Enabled() bool { return d != nil && len(d.byName) > 0 }

func newClient(hook config.Webhook) (*http.Client, error) {
	timeout := hook.Timeout.Std()
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // InsecureSkipVerify is set below, from an explicit opt-in
	if hook.SkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if hook.CAFile != "" {
		pem, err := os.ReadFile(hook.CAFile) //nolint:gosec // an operator-supplied path
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s contains no certificate", hook.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("the default HTTP transport has been replaced; cannot clone it")
	}
	transport := base.Clone()
	transport.TLSClientConfig = tlsCfg
	// A webhook receiver is one host: a handful of connections is plenty, and
	// a bounded pool keeps a flood of events from opening hundreds.
	transport.MaxIdleConnsPerHost = 4
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// A webhook URL is a destination, not a starting point: following a
		// redirect would let a receiver aim the signed body somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("the receiver answered with a redirect; webhooks are not followed")
		},
	}, nil
}

// Drain sends every delivery whose turn has come and returns what happened.
func (d *Deliverer) Drain(ctx context.Context, now time.Time) (sent, retried, failed int) {
	if !d.Enabled() {
		return 0, 0, 0
	}
	due, err := d.store.DueDeliveries(ctx, now, 100)
	if err != nil {
		d.log.Error("cannot read the webhook queue", "error", err.Error())
		return 0, 0, 0
	}
	for _, delivery := range due {
		if ctx.Err() != nil {
			return sent, retried, failed
		}
		switch d.deliver(ctx, delivery, now) {
		case outcomeSent:
			sent++
		case outcomeRetry:
			retried++
		case outcomeFailed:
			failed++
		}
	}
	return sent, retried, failed
}

type outcome int

const (
	outcomeSent outcome = iota
	outcomeRetry
	outcomeFailed
)

func (d *Deliverer) deliver(ctx context.Context, row store.Delivery, now time.Time) outcome {
	hook, ok := d.byName[row.Endpoint]
	if !ok {
		// The endpoint was removed from the configuration while its events
		// were queued. Dropping them quietly would be worse than saying so.
		_ = d.store.DeliveryFailed(ctx, row.ID, 0,
			"endpoint "+row.Endpoint+" is no longer configured", time.Time{}, now)
		d.log.Warn("queued webhook has no endpoint any more",
			"endpoint", row.Endpoint, "event", row.Event)
		return outcomeFailed
	}

	attempt := row.Attempts + 1
	status, err := d.post(ctx, hook, row, attempt)
	if err == nil {
		if markErr := d.store.DeliverySucceeded(ctx, row.ID, status, now); markErr != nil {
			d.log.Error("webhook delivered but not recorded", "error", markErr.Error())
		}
		d.log.Debug("webhook delivered",
			"endpoint", hook.Name, "event", row.Event, "status", status, "attempt", attempt)
		return outcomeSent
	}

	permanent := !retryable(status)
	if permanent || attempt >= hook.Attempts() {
		if markErr := d.store.DeliveryFailed(ctx, row.ID, status, err.Error(), time.Time{}, now); markErr != nil {
			d.log.Error("cannot record a failed webhook", "error", markErr.Error())
		}
		d.log.Error("webhook gave up",
			"endpoint", hook.Name, "event", row.Event, "attempts", attempt,
			"status", status, "permanent", permanent, "error", err.Error())
		return outcomeFailed
	}

	wait := config.WebhookBackoff(attempt)
	if markErr := d.store.DeliveryFailed(ctx, row.ID, status, err.Error(), now.Add(wait), now); markErr != nil {
		d.log.Error("cannot reschedule a webhook", "error", markErr.Error())
	}
	d.log.Warn("webhook attempt failed, will retry",
		"endpoint", hook.Name, "event", row.Event, "attempt", attempt,
		"status", status, "in", wait.String(), "error", err.Error())
	return outcomeRetry
}

// post sends one attempt. It returns the HTTP status when there was one, and
// an error describing what went wrong when the attempt did not arrive.
func (d *Deliverer) post(ctx context.Context, hook config.Webhook, row store.Delivery, attempt int) (int, error) {
	body := []byte(row.Payload)
	timestamp := time.Now().Unix()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", d.agent)
	req.Header.Set(HeaderEvent, row.Event)
	req.Header.Set(HeaderDelivery, row.ID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(HeaderAttempt, strconv.Itoa(attempt))
	req.Header.Set(HeaderSignature, Sign(hook.Secret, timestamp, body))
	req.ContentLength = int64(len(body))

	resp, err := d.clients[hook.Name].Do(req)
	if err != nil {
		// The URL can carry a credential in its query string, and the error
		// from net/http repeats the whole URL. Say the endpoint name instead.
		return 0, fmt.Errorf("cannot reach the receiver: %s", transportReason(err))
	}
	defer func() { _ = resp.Body.Close() }()
	// Read and discard a little of the body so the connection can be reused,
	// and so a receiver that explains itself is not left mid-write.
	explanation := readLimited(resp, 200)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, nil
	}
	if explanation != "" {
		return resp.StatusCode, fmt.Errorf("the receiver answered %d: %s", resp.StatusCode, explanation)
	}
	return resp.StatusCode, fmt.Errorf("the receiver answered %d", resp.StatusCode)
}

// retryable decides whether the status is worth another attempt.
//
// Server errors, a timeout and a rate limit are temporary by definition, and a
// transport failure (status 0) usually is too. Any other 4xx says the receiver
// understood and refused: retrying for six hours would only fill its logs.
func retryable(status int) bool {
	switch {
	case status == 0:
		return true
	case status == http.StatusRequestTimeout, status == http.StatusTooManyRequests:
		return true
	case status >= 500:
		return true
	default:
		return false
	}
}

// Ping sends a test delivery now, synchronously, and returns what the receiver
// said. This is peek webhook test: an operator should be able to prove the path
// works without waiting for a real secret to be read.
func (d *Deliverer) Ping(ctx context.Context, name string) (int, error) {
	hook, ok := d.byName[name]
	if !ok {
		return 0, fmt.Errorf("no webhook named %q is configured and enabled", name)
	}
	id, err := store.NewID()
	if err != nil {
		return 0, err
	}
	body, err := json.Marshal(Payload{
		ID:       id,
		Event:    PingEvent,
		At:       time.Now().UTC(),
		Instance: d.instance,
		Org:      store.DefaultOrgID,
		Detail:   map[string]string{"reason": "peek webhook test"},
	})
	if err != nil {
		return 0, err
	}
	return d.post(ctx, hook, store.Delivery{
		ID:      id,
		Event:   PingEvent,
		Payload: string(body),
	}, 1)
}

// Purge trims finished deliveries.
func (d *Deliverer) Purge(ctx context.Context, now time.Time) (int64, error) {
	if d == nil || d.store == nil {
		return 0, nil
	}
	return d.store.PurgeDeliveries(ctx, defaultQueueRetention, now)
}

// Describe returns one line for the startup log.
func (d *Deliverer) Describe() string {
	if !d.Enabled() {
		return "none"
	}
	parts := make([]string, 0, len(d.byName))
	for name, hook := range d.byName {
		parts = append(parts, fmt.Sprintf("%s (%d events, %d attempts)",
			name, len(hook.EventList()), hook.Attempts()))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// readLimited returns the first few bytes of a receiver's answer, on one line,
// so a failure in the queue says what the receiver complained about. It also
// drains enough of the body for the connection to be reusable.
func readLimited(resp *http.Response, n int) string {
	buf := make([]byte, n)
	read, _ := io.ReadFull(io.LimitReader(resp.Body, int64(n)), buf)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	text := strings.TrimSpace(string(buf[:read]))
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", "")
	return strings.TrimSpace(text)
}

// transportReason strips the URL out of a net/http error.
//
// A webhook URL may carry a token in its query string — several receivers are
// built that way — and net/http puts the whole URL in the error text. That
// text goes to the log and to the queue row, and rule one of this project is
// that no credential reaches either.
func transportReason(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}
