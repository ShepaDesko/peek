package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/store"
)

// apiError is the single error shape of the API.
type apiError struct {
	Error struct {
		Code         string `json:"code"`
		Message      string `json:"message"`
		Field        string `json:"field,omitempty"`
		AttemptsLeft *int   `json:"attempts_left,omitempty"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeError(w http.ResponseWriter, _ *http.Request, status int, code, message string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	writeJSON(w, status, e)
}

func writeFieldError(w http.ResponseWriter, status int, code, message, field string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	e.Error.Field = field
	writeJSON(w, status, e)
}

// notFound is the deliberately indistinguishable answer for a secret that is
// expired, already consumed, burned or never existed (spec section 3.3).
func notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "This link is no longer valid.")
}

// audit records an event, enriched with the resolved client IP and user agent.
// Called from handlers; failures are logged, never surfaced to the client.
func (s *Server) audit(r *http.Request, e store.AuditEvent) {
	if s.store == nil {
		return
	}
	if e.OrgID == "" {
		e.OrgID = "default"
	}
	ip := ClientIP(r.Context())
	if s.cfg.Security.AnonymizeIPs {
		ip = store.AnonymizeIP(ip)
	}
	e.IP = ip
	e.UserAgent = r.UserAgent()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if err := s.store.Append(r.Context(), e); err != nil {
		s.log.Error("cannot write audit event", "event", e.Event, "error", err.Error())
	}
	// The database copy is the record; the SIEM gets a best-effort copy.
	s.siem.Forward(e)
}

// ---------------------------------------------------------------------------
// Health and diagnostics
// ---------------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	type check struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
		Err  string `json:"error,omitempty"`
	}
	checks := make([]check, 0, 1)
	ready := true

	err := s.store.Ping(r.Context())
	checks = append(checks, check{Name: "database", OK: err == nil, Err: errString(err)})
	ready = ready && err == nil

	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "checks": checks})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true, "checks": checks})
}

func (s *Server) handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// handleWhoami reports the client IP as Peek resolved it. This is what makes
// a misconfigured X-Forwarded-For chain visible in one request, and what
// peek doctor --external calls.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"client_ip":          ClientIP(r.Context()),
		"peer_addr":          r.RemoteAddr,
		"scheme":             s.trusted.Scheme(r),
		"host":               s.trusted.ForwardedHost(r),
		"listener":           ListenerName(r.Context()),
		"trusted_peer":       s.trusted.Contains(peerIP(r)),
		"forwarded_honoured": s.trusted.Contains(peerIP(r)),
	})
}

func (s *Server) handleInstance(w http.ResponseWriter, r *http.Request) {
	active, err := s.store.CountActive(r.Context())
	if err != nil {
		s.log.Error("count active secrets", "error", err.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         s.version,
		"crypto_version":  pcrypto.Version,
		"uptime_seconds":  int(time.Since(s.started).Seconds()),
		"driver":          s.store.Driver(),
		"active_secrets":  active,
		"multi_org":       s.cfg.MultiOrg,
		"public_listener": s.cfg.Server.PublicListen != "",
	})
}

// ---------------------------------------------------------------------------
// Policy and branding
// ---------------------------------------------------------------------------

func (s *Server) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	p := s.cfg.Policy
	writeJSON(w, http.StatusOK, map[string]any{
		"max_ttl_seconds":         int(p.MaxTTL.Std().Seconds()),
		"default_ttl_seconds":     int(p.DefaultTTL.Std().Seconds()),
		"max_views":               p.MaxViews,
		"default_views":           p.DefaultViews,
		"require_passphrase":      p.RequirePassphrase,
		"force_retrieval_step":    p.ForceRetrievalStep,
		"allowed_kinds":           p.AllowedKinds,
		"max_file_bytes":          p.MaxFileBytes,
		"max_secret_bytes":        p.MaxSecretBytes,
		"max_recipients":          p.MaxRecipients,
		"max_passphrase_attempts": s.cfg.Security.MaxPassphraseTries,
		"kdf": map[string]any{
			"memory_kib":  pcrypto.DefaultMemoryKiB,
			"iterations":  pcrypto.DefaultIterations,
			"parallelism": pcrypto.DefaultParallelism,
		},
	})
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

type createRequest struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	Ciphertext       string `json:"ciphertext"`
	ReadTokenHash    string `json:"read_token_hash"`
	ReceiptTokenHash string `json:"receipt_token_hash"`
	KDF              struct {
		Salt        string `json:"salt"`
		MemoryKiB   uint32 `json:"memory_kib"`
		Iterations  uint32 `json:"iterations"`
		Parallelism uint8  `json:"parallelism"`
	} `json:"kdf"`
	HasPassphrase        bool   `json:"has_passphrase"`
	TTLSeconds           int    `json:"ttl_seconds"`
	Views                int    `json:"views"`
	RetrievalStep        *bool  `json:"retrieval_step"`
	DeletableByRecipient bool   `json:"deletable_by_recipient"`
	Label                string `json:"label_enc"`
	// NotifyEmail asks to be told when the secret is read. The address is
	// encrypted with the server master key before it is stored.
	NotifyEmail string `json:"notify_email"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	// Creating a secret needs either an account or an instance that allows
	// anonymous creation. Refusing by default is the safe side of that trade:
	// an exposed instance is not an open relay on day one.
	p := principalOf(r.Context())
	if p == nil && !s.cfg.Security.AnonymousCreate {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated",
			"Sign in to create a secret, or enable security.anonymous_create in peek.toml.")
		return
	}
	if p != nil && p.User.Role == store.RoleAuditor {
		writeError(w, r, http.StatusForbidden, "forbidden", "An auditor account cannot create secrets.")
		return
	}
	creatorID, orgID := "", store.DefaultOrgID
	if p != nil {
		creatorID, orgID = p.User.ID, p.User.OrgID
	}

	var req createRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	ciphertext, err := decodeB64Field(req.Ciphertext, "ciphertext")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "ciphertext")
		return
	}
	readHash, err := decodeB64Field(req.ReadTokenHash, "read_token_hash")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "read_token_hash")
		return
	}
	receiptHash, err := decodeB64Field(req.ReceiptTokenHash, "receipt_token_hash")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "receipt_token_hash")
		return
	}
	salt, err := decodeB64Field(req.KDF.Salt, "kdf.salt")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "kdf.salt")
		return
	}
	var label []byte
	if req.Label != "" {
		if label, err = decodeB64Field(req.Label, "label_enc"); err != nil {
			writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "label_enc")
			return
		}
	}

	retrieval := true
	if req.RetrievalStep != nil {
		retrieval = *req.RetrievalStep
	}

	var notifyEnc []byte
	if req.NotifyEmail != "" {
		if s.cipher == nil {
			writeFieldError(w, http.StatusServiceUnavailable, "no_master_key",
				"This instance has no master key, so a notification address cannot be stored.", "notify_email")
			return
		}
		sealed, err := s.cipher.SealString(pcrypto.PurposeEmail, strings.TrimSpace(req.NotifyEmail))
		if err != nil {
			s.log.Error("seal notification address", "error", err.Error())
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
			return
		}
		notifyEnc = sealed
	}

	created, err := s.secrets.Create(r.Context(), secrets.CreateInput{
		CreatorID:        creatorID,
		OrgID:            orgID,
		ID:               req.ID,
		Kind:             req.Kind,
		Ciphertext:       ciphertext,
		ReadTokenHash:    readHash,
		ReceiptTokenHash: receiptHash,
		KDF: pcrypto.KDFParams{
			Salt:        salt,
			MemoryKiB:   req.KDF.MemoryKiB,
			Iterations:  req.KDF.Iterations,
			Parallelism: req.KDF.Parallelism,
		},
		HasPassphrase:        req.HasPassphrase,
		TTL:                  time.Duration(req.TTLSeconds) * time.Second,
		Views:                req.Views,
		RetrievalStep:        retrieval,
		DeletableByRecipient: req.DeletableByRecipient,
		LabelEnc:             label,
		NotifyEmailEnc:       notifyEnc,
		NotifyOnView:         notifyEnc != nil,
	})
	switch {
	case err == nil:
	case errors.Is(err, secrets.ErrConflict):
		writeError(w, r, http.StatusConflict, "conflict", "This identifier is already in use. Retry with a new one.")
		return
	case errors.Is(err, secrets.ErrPolicy):
		var pe *secrets.PolicyError
		field := ""
		if errors.As(err, &pe) {
			field = pe.Field
		}
		writeFieldError(w, http.StatusUnprocessableEntity, "policy", err.Error(), field)
		return
	default:
		s.log.Error("create secret", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	s.audit(r, store.AuditEvent{
		SecretID: created.ID,
		UserID:   creatorID,
		Event:    store.EventCreated,
		Detail: map[string]string{
			"kind":           created.Kind,
			"views_max":      strconv.Itoa(created.ViewsMax),
			"has_passphrase": strconv.FormatBool(req.HasPassphrase),
			"size_bytes":     strconv.Itoa(len(ciphertext)),
		},
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleSecretMeta(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	meta, err := s.secrets.Meta(r.Context(), id)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventNotFound})
			notFound(w, r)
			return
		}
		s.log.Error("read secret metadata", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	// Looking at the page is not reading the secret: no view is consumed here,
	// which is what keeps link-preview bots harmless.
	s.audit(r, store.AuditEvent{SecretID: meta.ID, Event: store.EventPageViewed})

	writeJSON(w, http.StatusOK, map[string]any{
		"id":                     meta.ID,
		"kind":                   meta.Kind,
		"has_passphrase":         meta.HasPassphrase,
		"retrieval_step":         meta.RetrievalStep,
		"deletable_by_recipient": meta.Deletable,
		"views_remaining":        meta.ViewsRemaining,
		"views_max":              meta.ViewsMax,
		"expires_at":             meta.ExpiresAt,
		"size_bytes":             meta.SizeBytes,
		"attempts_left":          meta.AttemptsLeft,
		"kdf": map[string]any{
			"salt":        pcrypto.B64.EncodeToString(meta.KDF.Salt),
			"memory_kib":  meta.KDF.MemoryKiB,
			"iterations":  meta.KDF.Iterations,
			"parallelism": meta.KDF.Parallelism,
		},
	})
}

type revealRequest struct {
	ReadToken string `json:"read_token"`
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req revealRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	token, err := decodeB64Field(req.ReadToken, "read_token")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "read_token")
		return
	}

	rev, attemptsLeft, err := s.secrets.Reveal(r.Context(), id, token)
	switch {
	case err == nil:
	case errors.Is(err, secrets.ErrNotFound):
		s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventNotFound})
		notFound(w, r)
		return
	case errors.Is(err, secrets.ErrLocked):
		s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventBurned,
			Detail: map[string]string{"reason": "too_many_failed_attempts"}})
		writeError(w, r, http.StatusGone, "locked",
			"Too many failed attempts: the secret has been destroyed.")
		return
	case errors.Is(err, secrets.ErrBadToken):
		s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventBadPassphrase,
			Detail: map[string]string{"attempts_left": strconv.Itoa(attemptsLeft)}})
		var e apiError
		e.Error.Code = "bad_token"
		e.Error.Message = "Wrong passphrase, or the link is incomplete."
		left := attemptsLeft
		e.Error.AttemptsLeft = &left
		writeJSON(w, http.StatusForbidden, e)
		return
	default:
		s.log.Error("reveal secret", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	s.notifySender(r, id, rev)
	s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventRevealed,
		Detail: map[string]string{
			"views_remaining": strconv.Itoa(rev.ViewsRemaining),
			"destroyed":       strconv.FormatBool(rev.Destroyed),
		}})
	writeJSON(w, http.StatusOK, map[string]any{
		"kind":            rev.Kind,
		"ciphertext":      pcrypto.B64.EncodeToString(rev.Ciphertext),
		"views_remaining": rev.ViewsRemaining,
		"destroyed":       rev.Destroyed,
		"size_bytes":      rev.SizeBytes,
	})
}

func (s *Server) handleRecipientDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, err := tokenFromHeaderOrBody(r, "read_token")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.secrets.DeleteByRecipient(r.Context(), id, token); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			notFound(w, r)
			return
		}
		s.log.Error("recipient delete", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventDeleted,
		Detail: map[string]string{"by": "recipient"}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReceipt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, err := tokenFromHeaderOrBody(r, "receipt_token")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	receipt, err := s.secrets.Receipt(r.Context(), id, token)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			notFound(w, r)
			return
		}
		s.log.Error("read receipt", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              receipt.ID,
		"status":          receipt.Status,
		"kind":            receipt.Kind,
		"views_used":      receipt.ViewsUsed,
		"views_max":       receipt.ViewsMax,
		"views_remaining": receipt.ViewsRemaining,
		"created_at":      receipt.CreatedAt,
		"expires_at":      nilTime(receipt.ExpiresAt),
		"last_viewed_at":  nilTime(receipt.LastViewedAt),
		"has_passphrase":  receipt.HasPassphrase,
		"url":             s.cfg.SecretURL(receipt.ID),
	})
}

func (s *Server) handleBurn(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, err := tokenFromHeaderOrBody(r, "receipt_token")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.secrets.Burn(r.Context(), id, token); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			notFound(w, r)
			return
		}
		s.log.Error("burn secret", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventBurned,
		Detail: map[string]string{"by": "sender"}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	events, err := s.store.ListAudit(r.Context(), store.AuditFilter{
		SecretID: q.Get("secret_id"),
		Event:    q.Get("event"),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		s.log.Error("list audit", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// errMalformedBody is the single answer for a body we cannot parse.
var errMalformedBody = errors.New("malformed JSON body")

func decodeJSON(r *http.Request, dst any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("expected Content-Type application/json")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body too large")
		}
		return errMalformedBody
	}
	return nil
}

func decodeB64Field(value, field string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	b, err := pcrypto.B64.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be unpadded base64url", field)
	}
	return b, nil
}

// tokenFromHeaderOrBody reads a 32-byte token. The header form keeps it out of
// the URL, and therefore out of proxy logs.
func tokenFromHeaderOrBody(r *http.Request, field string) ([]byte, error) {
	if v := r.Header.Get("X-Peek-Token"); v != "" {
		return decodeB64Field(v, field)
	}
	if r.Body == nil || r.ContentLength == 0 {
		return nil, fmt.Errorf("%s is required (send it in the X-Peek-Token header or the JSON body)", field)
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("malformed JSON body")
	}
	return decodeB64Field(body[field], field)
}

// safeID avoids writing attacker-controlled junk into the audit trail.
func safeID(id string) string {
	if pcrypto.ValidID(id) {
		return id
	}
	return ""
}

func nilTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// notifySender tells the creator their secret was read, when they asked for it.
//
// It runs in the background: the recipient is waiting for their secret, and a
// slow mail relay must not hold that up. Failures are logged, never surfaced
// to the recipient, who has nothing to do with them.
func (s *Server) notifySender(r *http.Request, secretID string, rev store.Reveal) {
	if len(rev.NotifyEmailEnc) == 0 || s.cipher == nil || !s.mailer.Configured() {
		return
	}
	address, err := s.cipher.OpenString(pcrypto.PurposeEmail, rev.NotifyEmailEnc)
	if err != nil {
		s.log.Error("cannot read the notification address", "error", err.Error())
		return
	}
	destroyed := rev.Destroyed
	id := safeID(secretID)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.mailSecretViewed(ctx, address, id, destroyed); err != nil {
			s.log.Error("cannot send the read notification", "error", err.Error())
		}
	}()
	_ = r
}
