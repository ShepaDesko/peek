package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/requests"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/store"
)

// Secret requests over HTTP.
//
// Two of these routes are recipient-facing and live on both listeners: reading
// a request's metadata, and depositing an answer. Everything else — creating a
// request, following it, closing it — is internal, like creating a secret.

type createRequestBody struct {
	ID               string  `json:"id"`
	PublicKey        string  `json:"public_key"`
	ReadTokenHash    string  `json:"read_token_hash"`
	ReceiptTokenHash string  `json:"receipt_token_hash"`
	PromptEnc        string  `json:"prompt_enc"`
	KDF              kdfBody `json:"kdf"`
	Label            string  `json:"label_enc"`
	TTLSeconds       int     `json:"ttl_seconds"`
	MaxDeposits      int     `json:"max_deposits"`
	NotifyEmail      string  `json:"notify_email"`
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil && !s.cfg.Security.AnonymousCreate {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated",
			"Sign in to create a secret request, or enable security.anonymous_create in peek.toml.")
		return
	}
	if p != nil && p.User.Role == store.RoleAuditor {
		writeError(w, r, http.StatusForbidden, "forbidden", "An auditor account cannot create secret requests.")
		return
	}
	creatorID, orgID := "", store.DefaultOrgID
	if p != nil {
		creatorID, orgID = p.User.ID, p.User.OrgID
	}

	var body createRequestBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	fields := map[string]string{
		"public_key":         body.PublicKey,
		"read_token_hash":    body.ReadTokenHash,
		"receipt_token_hash": body.ReceiptTokenHash,
		"kdf.salt":           body.KDF.Salt,
	}
	decoded := map[string][]byte{}
	for name, raw := range fields {
		v, err := decodeB64Field(raw, name)
		if err != nil {
			writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), name)
			return
		}
		decoded[name] = v
	}
	var prompt, label []byte
	var err error
	if body.PromptEnc != "" {
		if prompt, err = decodeB64Field(body.PromptEnc, "prompt_enc"); err != nil {
			writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "prompt_enc")
			return
		}
	}
	if body.Label != "" {
		if label, err = decodeB64Field(body.Label, "label_enc"); err != nil {
			writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "label_enc")
			return
		}
	}

	var notifyEnc []byte
	if body.NotifyEmail != "" {
		if s.cipher == nil {
			writeFieldError(w, http.StatusServiceUnavailable, "no_master_key",
				"This instance has no master key, so a notification address cannot be stored.", "notify_email")
			return
		}
		sealed, err := s.cipher.SealString(pcrypto.PurposeEmail, strings.TrimSpace(body.NotifyEmail))
		if err != nil {
			s.log.Error("seal notification address", "error", err.Error())
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
			return
		}
		notifyEnc = sealed
	}

	created, err := s.requests.Create(r.Context(), requests.CreateInput{
		ID:               body.ID,
		OrgID:            orgID,
		CreatorID:        creatorID,
		PublicKey:        decoded["public_key"],
		ReadTokenHash:    decoded["read_token_hash"],
		ReceiptTokenHash: decoded["receipt_token_hash"],
		PromptEnc:        prompt,
		KDF: pcrypto.KDFParams{
			Salt:        decoded["kdf.salt"],
			MemoryKiB:   body.KDF.MemoryKiB,
			Iterations:  body.KDF.Iterations,
			Parallelism: body.KDF.Parallelism,
		},
		LabelEnc:       label,
		NotifyEmailEnc: notifyEnc,
		TTL:            time.Duration(body.TTLSeconds) * time.Second,
		MaxDeposits:    body.MaxDeposits,
	})
	if !s.writeRequestError(w, r, err, "create secret request") {
		return
	}

	s.audit(r, store.AuditEvent{
		OrgID:    orgID,
		SecretID: created.ID,
		UserID:   creatorID,
		Event:    store.EventRequestCreated,
		Detail:   map[string]string{"max_deposits": strconv.Itoa(created.MaxDeposits)},
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleRequestMeta(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	m, err := s.requests.Meta(r.Context(), id)
	if err != nil {
		if errors.Is(err, requests.ErrNotFound) {
			s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventRequestNotFound})
			notFound(w, r)
			return
		}
		s.log.Error("read request metadata", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                 m.ID,
		"deposits_remaining": m.DepositsRemaining,
		"expires_at":         m.ExpiresAt,
		"kdf": map[string]any{
			"salt":        pcrypto.B64.EncodeToString(m.KDF.Salt),
			"memory_kib":  m.KDF.MemoryKiB,
			"iterations":  m.KDF.Iterations,
			"parallelism": m.KDF.Parallelism,
		},
	})
}

type openRequestBody struct {
	ReadToken string `json:"read_token"`
}

// handleOpenRequest releases the prompt to whoever holds the request key. It
// consumes nothing: the prompt is not the answer, and a depositor may well
// reload the page before they are ready to send.
func (s *Server) handleOpenRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body openRequestBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	token, err := decodeB64Field(body.ReadToken, "read_token")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "read_token")
		return
	}

	out, err := s.requests.Open(r.Context(), id, token)
	switch {
	case err == nil:
	case errors.Is(err, requests.ErrNotFound):
		s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventRequestNotFound})
		notFound(w, r)
		return
	case errors.Is(err, requests.ErrBadToken):
		writeError(w, r, http.StatusForbidden, "bad_token", "This link is incomplete.")
		return
	default:
		s.log.Error("open secret request", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	s.audit(r, store.AuditEvent{SecretID: out.ID, Event: store.EventRequestOpened})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         out.ID,
		"prompt_enc": pcrypto.B64.EncodeToString(out.PromptEnc),
		"expires_at": out.ExpiresAt,
	})
}

type depositBody struct {
	ReadToken  string        `json:"read_token"`
	WrappedKey string        `json:"wrapped_key"`
	Secret     recipientBody `json:"secret"`
	Files      []fileRefBody `json:"files"`
}

func (s *Server) handleDeposit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body depositBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	token, err := decodeB64Field(body.ReadToken, "read_token")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "read_token")
		return
	}
	wrapped, err := decodeB64Field(body.WrappedKey, "wrapped_key")
	if err != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", err.Error(), "wrapped_key")
		return
	}

	// The organisation is the request's, not the depositor's: an answer
	// belongs to whoever asked.
	in, ferr := s.recipientInput(body.Secret, "", "")
	if ferr != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", ferr.message, ferr.field)
		return
	}
	files, ferr := decodeFileRefs(body.Files)
	if ferr != nil {
		writeFieldError(w, http.StatusBadRequest, "bad_request", ferr.message, ferr.field)
		return
	}
	in.Files = files

	out, err := s.requests.Deposit(r.Context(), id, requests.DepositInput{
		Secret:     in,
		WrappedKey: wrapped,
		ReadToken:  token,
	})
	switch {
	case err == nil:
	case errors.Is(err, requests.ErrNotFound):
		s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventRequestNotFound})
		notFound(w, r)
		return
	case errors.Is(err, requests.ErrBadToken):
		writeError(w, r, http.StatusForbidden, "bad_token", "This link is incomplete.")
		return
	case errors.Is(err, requests.ErrClosed):
		writeError(w, r, http.StatusGone, "closed", "This request has already been answered.")
		return
	default:
		if !s.writeRequestError(w, r, err, "deposit on a secret request") {
			return
		}
	}

	s.notifyRequester(r, id, out)
	s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventRequestDeposited,
		Detail: map[string]string{"secret_id": out.ID}})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         out.ID,
		"created_at": out.CreatedAt,
	})
}

func (s *Server) handleRequestReceipt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, err := tokenFromHeaderOrBody(r, "receipt_token")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	rec, err := s.requests.Receipt(r.Context(), id, token)
	if err != nil {
		if errors.Is(err, requests.ErrNotFound) {
			notFound(w, r)
			return
		}
		s.log.Error("read request receipt", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	deposits := make([]map[string]any, 0, len(rec.Deposits))
	for _, d := range rec.Deposits {
		deposits = append(deposits, map[string]any{
			"secret_id":       d.SecretID,
			"wrapped_key":     pcrypto.B64.EncodeToString(d.WrappedKey),
			"has_passphrase":  d.HasPassphrase,
			"size_bytes":      d.SizeBytes,
			"created_at":      d.CreatedAt,
			"views_remaining": d.ViewsRemaining,
			"kdf": map[string]any{
				"salt":        pcrypto.B64.EncodeToString(d.KDF.Salt),
				"memory_kib":  d.KDF.MemoryKiB,
				"iterations":  d.KDF.Iterations,
				"parallelism": d.KDF.Parallelism,
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                 rec.ID,
		"label_enc":          pcrypto.B64.EncodeToString(rec.LabelEnc),
		"max_deposits":       rec.MaxDeposits,
		"deposits_used":      rec.DepositsUsed,
		"deposits_remaining": rec.DepositsRemaining,
		"created_at":         rec.CreatedAt,
		"expires_at":         rec.ExpiresAt,
		"deposits":           deposits,
	})
}

func (s *Server) handleCloseRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token, err := tokenFromHeaderOrBody(r, "receipt_token")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.requests.Close(r.Context(), id, token); err != nil {
		if errors.Is(err, requests.ErrNotFound) {
			notFound(w, r)
			return
		}
		s.log.Error("close secret request", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	s.audit(r, store.AuditEvent{SecretID: safeID(id), Event: store.EventRequestClosed})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in first.")
		return
	}
	list, err := s.requests.List(r.Context(), p.User.ID, 100)
	if err != nil {
		s.log.Error("list secret requests", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, rq := range list {
		out = append(out, map[string]any{
			"id":                 rq.ID,
			"label_enc":          pcrypto.B64.EncodeToString(rq.LabelEnc),
			"max_deposits":       rq.MaxDeposits,
			"deposits_used":      rq.DepositsUsed,
			"deposits_remaining": rq.DepositsRemaining,
			"created_at":         rq.CreatedAt,
			"expires_at":         rq.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// writeRequestError maps the shared error vocabulary once. It returns false
// when it has written a response and the caller must stop.
func (s *Server) writeRequestError(w http.ResponseWriter, r *http.Request, err error, what string) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, secrets.ErrConflict):
		writeError(w, r, http.StatusConflict, "conflict", "This identifier is already in use. Retry with a new one.")
	case errors.Is(err, secrets.ErrPolicy):
		var pe *secrets.PolicyError
		field := ""
		if errors.As(err, &pe) {
			field = pe.Field
		}
		writeFieldError(w, http.StatusUnprocessableEntity, "policy", err.Error(), field)
	default:
		s.log.Error(what, "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
	}
	return false
}

// notifyRequester tells the requester that an answer arrived, when they asked
// to be told. Like the read notification it runs in the background: the
// depositor is waiting for a confirmation and a slow relay must not hold that
// up, and a mail failure is none of their business.
func (s *Server) notifyRequester(r *http.Request, requestID string, out requests.Deposited) {
	if len(out.NotifyEmailEnc) == 0 || s.cipher == nil || !s.mailer.Configured() {
		return
	}
	address, err := s.cipher.OpenString(pcrypto.PurposeEmail, out.NotifyEmailEnc)
	if err != nil {
		s.log.Error("cannot read the notification address", "error", err.Error())
		return
	}
	id := safeID(requestID)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.mailRequestDeposited(ctx, address, id); err != nil {
			s.log.Error("cannot send the deposit notification", "error", err.Error())
		}
	}()
	_ = r
}
