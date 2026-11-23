package server

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/store"
	"github.com/ShepaDesko/peek/internal/webhooks"
)

// The webhook surface an administrator sees.
//
// There is no endpoint that creates a webhook. Endpoints live in peek.toml
// because a URL the API could set would turn the server into a request
// forwarder aimed at the operator's own network. What the API offers instead
// is what an operator actually needs at three in the morning: what is
// configured, what is stuck, why, and a way to send one again.

type webhookEndpoint struct {
	Name   string   `json:"name"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	// Attempts is the budget including the first try.
	Attempts int    `json:"max_attempts"`
	Timeout  string `json:"timeout"`
	Disabled bool   `json:"disabled"`
	// Insecure flags an endpoint whose TLS verification is off, so the admin
	// page can mark it rather than leave it looking like the others.
	Insecure bool `json:"insecure,omitempty"`
}

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	out := make([]webhookEndpoint, 0, len(s.cfg.Webhooks))
	for _, hook := range s.cfg.Webhooks {
		timeout := hook.Timeout.Std()
		if timeout <= 0 {
			timeout = webhooks.DefaultTimeout
		}
		out = append(out, webhookEndpoint{
			Name:     hook.Name,
			URL:      redactQuery(hook.URL),
			Events:   hook.EventList(),
			Attempts: hook.Attempts(),
			Timeout:  timeout.String(),
			Disabled: hook.Disabled,
			Insecure: hook.SkipVerify,
		})
	}

	stats, err := s.store.DeliveryStats(r.Context())
	if err != nil {
		s.log.Error("webhook queue stats", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "server_error", "Could not read the queue.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoints": out,
		"queue":     stats,
		// The signature scheme, so a receiver can be written from the API
		// response alone rather than from the documentation.
		"signature": map[string]any{
			"algorithm": "HMAC-SHA256",
			"version":   webhooks.SignatureVersion,
			"signed":    "<x-peek-timestamp>.<body>",
			"headers": []string{
				webhooks.HeaderEvent, webhooks.HeaderDelivery,
				webhooks.HeaderTimestamp, webhooks.HeaderAttempt, webhooks.HeaderSignature,
			},
		},
	})
}

func (s *Server) handleWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	switch state {
	case "", "pending", "delivered", "failed":
	default:
		writeError(w, r, http.StatusBadRequest, "bad_state",
			"state must be pending, delivered or failed.")
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	list, err := s.store.ListDeliveries(r.Context(), store.DeliveryFilter{
		Endpoint: q.Get("endpoint"),
		Event:    q.Get("event"),
		State:    state,
		Limit:    limit,
	})
	if err != nil {
		s.log.Error("list webhook deliveries", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "server_error", "Could not read the queue.")
		return
	}
	if list == nil {
		list = []store.Delivery{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": list})
}

// handleWebhookTest sends one ping, synchronously, and reports what the
// receiver said. An operator should never have to read a real secret to find
// out whether the path works.
func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !s.hooks.Enabled() {
		writeError(w, r, http.StatusConflict, "no_webhooks",
			"No webhook is configured. Declare one as [[webhook]] in peek.toml.")
		return
	}
	// Bounded here as well as in the client: an operator waiting on a reply
	// should get one, even from a receiver that accepts the connection and
	// then says nothing.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	status, err := s.hooks.Ping(ctx, name)
	s.audit(r, store.AuditEvent{
		Event:  store.EventWebhookTested,
		UserID: principalOf(r.Context()).User.ID,
		Detail: map[string]string{"endpoint": name, "ok": boolString(err == nil)},
	})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"status": status,
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
}

// handleWebhookRetry puts failed deliveries back in the queue. The usual
// sequence is: the receiver was down, the operator fixed it, and now wants the
// events that were lost in the meantime.
func (s *Server) handleWebhookRetry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Endpoint string `json:"endpoint"`
	}
	// An empty body means "every failed delivery", which is the common case.
	_ = decodeJSON(r, &req)

	now := time.Now()
	if req.ID != "" {
		ok, err := s.store.RetryDelivery(r.Context(), req.ID, now)
		if err != nil {
			s.log.Error("retry webhook delivery", "error", err.Error())
			writeError(w, r, http.StatusInternalServerError, "server_error", "Could not requeue it.")
			return
		}
		if !ok {
			writeError(w, r, http.StatusNotFound, "not_found",
				"No failed delivery with that identifier.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requeued": 1})
		return
	}

	n, err := s.store.RetryFailedDeliveries(r.Context(), req.Endpoint, now)
	if err != nil {
		s.log.Error("retry failed webhooks", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "server_error", "Could not requeue them.")
		return
	}
	s.audit(r, store.AuditEvent{
		Event:  store.EventWebhookRequeued,
		UserID: principalOf(r.Context()).User.ID,
		Detail: map[string]string{
			"endpoint": orAll(req.Endpoint),
			"count":    strconv.FormatInt(n, 10),
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{"requeued": n})
}

// redactQuery strips the query string from a webhook URL before it leaves the
// instance.
//
// Several receivers authenticate by a token in the query string — Mattermost,
// Teams and Slack incoming hooks all do. peek.toml is readable only by root
// and the service account, but this endpoint is reachable with an
// instance:read API token, which a monitoring script may hold. The host and
// the path are what an operator needs to recognise the endpoint; the token
// after the question mark is not.
func redactQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.RawQuery == "" && u.Fragment == "" {
		return raw
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String() + "?…"
}

// orAll names the whole queue in an audit entry, rather than leaving the field
// empty and ambiguous.
func orAll(endpoint string) string {
	if endpoint == "" {
		return "(all)"
	}
	return endpoint
}
