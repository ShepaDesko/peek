package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/store"
)

// API tokens over HTTP.
//
// A token is created with a session, never with another token: letting a token
// mint tokens would turn one leak into a permanent foothold. The clear text is
// returned exactly once, in the creation response, and the interface says so.

type createTokenRequest struct {
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	TTLSeconds int      `json:"ttl_seconds"`
}

func tokenJSON(t store.APIToken) map[string]any {
	out := map[string]any{
		"id":         t.ID,
		"name":       t.Name,
		"scopes":     t.Scopes,
		"created_at": t.CreatedAt,
		"revoked":    !t.RevokedAt.IsZero(),
	}
	if !t.ExpiresAt.IsZero() {
		out["expires_at"] = t.ExpiresAt
	}
	if !t.LastUsedAt.IsZero() {
		out["last_used_at"] = t.LastUsedAt
	}
	if !t.RevokedAt.IsZero() {
		out["revoked_at"] = t.RevokedAt
	}
	return out
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
		return
	}
	if p.IsToken() {
		// One leak must not become a key factory.
		writeError(w, r, http.StatusForbidden, "forbidden",
			"An API token cannot create another token. Sign in to the interface.")
		return
	}

	var req createTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	issued, err := s.accounts.CreateToken(r.Context(), p.User.ID, req.Name, req.Scopes,
		time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		// Every failure here is the caller's input: an unknown scope, an empty
		// name, a scope an auditor may not hold.
		writeFieldError(w, http.StatusUnprocessableEntity, "policy", err.Error(), "scopes")
		return
	}

	s.audit(r, store.AuditEvent{
		OrgID:  p.User.OrgID,
		UserID: p.User.ID,
		Event:  store.EventTokenCreated,
		Detail: map[string]string{
			"token":  issued.Token.Name,
			"id":     issued.Token.ID,
			"scopes": strings.Join(issued.Token.Scopes, " "),
		},
	})

	body := tokenJSON(issued.Token)
	// The one and only time the clear text leaves the server.
	body["token"] = issued.Secret
	writeJSON(w, http.StatusCreated, body)
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
		return
	}
	tokens, err := s.accounts.ListTokens(r.Context(), p.User.ID)
	if err != nil {
		s.log.Error("list api tokens", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	out := make([]map[string]any, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out, "scopes": store.AllScopes})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
		return
	}
	id := chi.URLParam(r, "id")

	// An administrator may revoke anyone's token: a colleague leaves, their
	// scripts must stop, and waiting for them to log in is not an option.
	owner := p.User.ID
	if p.User.Can(store.RoleAdmin) {
		owner = ""
	}
	if err := s.accounts.RevokeToken(r.Context(), id, owner); err != nil {
		notFound(w, r)
		return
	}
	s.audit(r, store.AuditEvent{
		OrgID:  p.User.OrgID,
		UserID: p.User.ID,
		Event:  store.EventTokenRevoked,
		Detail: map[string]string{"id": safeID(id)},
	})
	w.WriteHeader(http.StatusNoContent)
}
