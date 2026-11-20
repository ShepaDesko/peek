package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/store"
)

// WebAuthn endpoints.
//
// The browser's credential API takes and returns opaque structures, so these
// handlers pass them through rather than reshaping them. The challenge id is
// ours: it names a row that lives for five minutes and is deleted on use.

const maxCeremonyBytes = 64 << 10

func (s *Server) handlePasskeyRegisterStart(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	options, challenge, err := s.accounts.StartPasskeyRegistration(r.Context(), p)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": options, "challenge_id": challenge})
}

type passkeyFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Name        string          `json:"name"`
	Response    json.RawMessage `json:"response"`
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req passkeyFinishRequest
	if err := decodeCeremony(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	key, err := s.accounts.FinishPasskeyRegistration(r.Context(), p, req.ChallengeID, req.Name, req.Response)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventPasskeyRegistered,
		Detail: map[string]string{"passkey": key.ID}})
	writeJSON(w, http.StatusCreated, map[string]any{"passkey": publicPasskey(key)})
}

func (s *Server) handlePasskeyLoginStart(w http.ResponseWriter, r *http.Request) {
	options, challenge, err := s.accounts.StartPasskeyLogin(r.Context())
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": options, "challenge_id": challenge})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req passkeyFinishRequest
	if err := decodeCeremony(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	res, err := s.accounts.FinishPasskeyLogin(r.Context(), req.ChallengeID, req.Response,
		ClientIP(r.Context()), r.UserAgent())
	if err != nil {
		s.audit(r, store.AuditEvent{Event: store.EventLoginFailed,
			Detail: map[string]string{"method": "passkey"}})
		s.writeAccountError(w, r, err)
		return
	}
	s.setSessionCookies(w, r, res.SessionToken, res.CSRFToken, res.ExpiresAt)
	s.audit(r, store.AuditEvent{UserID: res.User.ID, Event: store.EventPasskeyLogin})
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       publicUser(res.User),
		"csrf_token": res.CSRFToken,
	})
}

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	keys, err := s.accounts.ListPasskeys(r.Context(), p)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, publicPasskey(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"passkeys":  out,
		"supported": s.accounts.PasskeySupported(),
	})
}

type renamePasskeyRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleRenamePasskey(w http.ResponseWriter, r *http.Request) {
	var req renamePasskeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	if err := s.accounts.RenamePasskey(r.Context(), p, chi.URLParam(r, "id"), req.Name); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.accounts.DeletePasskey(r.Context(), p, id); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventPasskeyRemoved,
		Detail: map[string]string{"passkey": id}})
	w.WriteHeader(http.StatusNoContent)
}

func publicPasskey(k store.Passkey) map[string]any {
	return map[string]any{
		"id":            k.ID,
		"name":          k.Name,
		"credential_id": accounts.EncodeCredentialID(k.CredentialID),
		"created_at":    k.CreatedAt,
		"last_used_at":  nilTime(k.LastUsedAt),
		"backed_up":     k.BackedUp,
		"transports":    k.Transports,
	}
}

// decodeCeremony reads a WebAuthn request body, which carries a raw structure
// from the browser and is therefore not checked for unknown fields.
func decodeCeremony(r *http.Request, dst any) error {
	body := io.LimitReader(r.Body, maxCeremonyBytes)
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		return errMalformedBody
	}
	return nil
}
