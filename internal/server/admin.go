package server

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/store"
)

// User management, invitations, the sender dashboard and the audit exports.

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	users, err := s.accounts.ListUsers(r.Context(), p)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

type createUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Password    string `json:"password"`
	Invite      bool   `json:"invite"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())

	// "Invite" is the normal path: the person chooses their own password.
	if req.Invite || req.Password == "" {
		inv, err := s.accounts.Invite(r.Context(), p, req.Email, req.Role)
		if err != nil {
			s.writeAccountError(w, r, err)
			return
		}
		s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventInvitationSent,
			Detail: map[string]string{"email": store.NormalizeEmail(req.Email), "role": inv.Record.Role}})

		link := s.publicLink(r.Context(), "/invitation#"+inv.Token)
		sendErr := s.mailInvitation(r.Context(), inv.Record.Email, inv.Token, displayName(p.User))
		writeJSON(w, http.StatusCreated, map[string]any{
			"invited":    true,
			"email":      inv.Record.Email,
			"role":       inv.Record.Role,
			"expires_at": inv.Record.ExpiresAt,
			// Returned so an instance without SMTP can still hand the link
			// over by another channel, which is the common on-premise case.
			"link":       link,
			"mail_sent":  sendErr == nil,
			"mail_error": errorText(sendErr),
		})
		return
	}

	user, err := s.accounts.CreateUser(r.Context(), p, accounts.CreateUserInput{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Role:        req.Role,
		Password:    req.Password,
	})
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventUserCreated,
		Detail: map[string]string{"created": user.ID, "role": user.Role}})
	writeJSON(w, http.StatusCreated, map[string]any{"user": publicUser(user)})
}

type updateUserRequest struct {
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Status      string `json:"status"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.accounts.UpdateUser(r.Context(), p, id, req.DisplayName, req.Role, req.Status); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventUserUpdated,
		Detail: map[string]string{"target": id, "role": req.Role, "status": req.Status}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.accounts.DeleteUser(r.Context(), p, id); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventUserDeleted,
		Detail: map[string]string{"target": id}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req passwordConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.accounts.SetUserPassword(r.Context(), p, id, req.Password); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventUserPasswordSet,
		Detail: map[string]string{"target": id}})
	w.WriteHeader(http.StatusNoContent)
}

// handleUnlinkSSO detaches a directory identity from an account.
//
// This is the way out of the one state an operator can otherwise get stuck in:
// a subject linked to the wrong account — a provider that reassigned a
// mailbox, a tenant migration, a mistake. Unlink, and the next sign-in links
// the subject afresh.
func (s *Server) handleUnlinkSSO(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not_found", "No such account.")
		return
	}
	if !user.FromDirectory() {
		writeError(w, r, http.StatusConflict, "not_linked",
			"That account is not linked to the identity provider.")
		return
	}
	// An account with no local credential and no directory identity cannot
	// sign in at all. Say so rather than creating one.
	if user.PasswordHash == "" {
		writeError(w, r, http.StatusConflict, "would_orphan",
			"That account has no password, so unlinking it would leave no way in. "+
				"Set a password for it first.")
		return
	}
	if err := s.store.UnlinkSSO(r.Context(), id); err != nil {
		s.log.Error("unlink sso identity", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventSSOUnlinked,
		Detail: map[string]string{"target": id}})
	w.WriteHeader(http.StatusNoContent)
}

// --- invitations -------------------------------------------------------------

func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	invitations, err := s.accounts.ListInvitations(r.Context(), p)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(invitations))
	for _, inv := range invitations {
		out = append(out, map[string]any{
			"id":         inv.ID,
			"email":      inv.Email,
			"role":       inv.Role,
			"created_at": inv.CreatedAt,
			"expires_at": inv.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": out})
}

func (s *Server) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.accounts.RevokeInvitation(r.Context(), p, id); err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventInvitationRevoked,
		Detail: map[string]string{"invitation": id}})
	w.WriteHeader(http.StatusNoContent)
}

type invitationTokenRequest struct {
	Token string `json:"token"`
}

// handlePreviewInvitation answers the acceptance page.
func (s *Server) handlePreviewInvitation(w http.ResponseWriter, r *http.Request) {
	var req invitationTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	preview, err := s.accounts.PreviewInvitation(r.Context(), req.Token)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not_found", "This invitation is no longer valid.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email":       preview.Email,
		"role":        preview.Role,
		"new_account": preview.NewAccount,
	})
}

type acceptInvitationRequest struct {
	Token       string `json:"token"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req acceptInvitationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	user, err := s.accounts.AcceptInvitation(r.Context(), req.Token, req.Password, req.DisplayName)
	if err != nil {
		s.writeAccountError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{UserID: user.ID, Event: store.EventInvitationAccepted})

	res, err := s.accounts.Login(r.Context(), user.OrgID, user.Email, req.Password, ClientIP(r.Context()), r.UserAgent())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
		return
	}
	s.setSessionCookies(w, r, res.SessionToken, res.CSRFToken, res.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user), "csrf_token": res.CSRFToken})
}

// --- dashboard ---------------------------------------------------------------

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	items, err := s.store.ListSecretsByCreator(r.Context(), store.DashboardFilter{
		OrgID:     p.User.OrgID,
		CreatorID: p.User.ID,
		Status:    q.Get("status"),
		Limit:     limit,
		Offset:    offset,
	}, time.Now())
	if err != nil {
		s.log.Error("dashboard", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	live, closed, err := s.store.CountSecretsByCreator(r.Context(), p.User.OrgID, p.User.ID)
	if err != nil {
		s.log.Error("dashboard counts", "error", err.Error())
	}
	if items == nil {
		items = []store.SecretSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secrets": items,
		"counts":  map[string]int{"live": live, "closed": closed},
	})
}

// handleBurnOwned destroys a secret from the dashboard, without the receipt
// token: the creator column is the proof of ownership here.
func (s *Server) handleBurnOwned(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.store.BurnAsOwner(r.Context(), p.User.OrgID, p.User.ID, id, time.Now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound(w, r)
			return
		}
		s.log.Error("burn owned secret", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, SecretID: safeID(id), Event: store.EventBurned,
		Detail: map[string]string{"by": "owner"}})
	w.WriteHeader(http.StatusNoContent)
}

// --- audit export ------------------------------------------------------------

// handleAuditExport streams the audit trail as CSV or JSON, for a SIEM or an
// auditor who wants it in a spreadsheet.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.AuditFilter{
		SecretID: q.Get("secret_id"),
		Event:    q.Get("event"),
		Limit:    1000,
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = t
		}
	}

	format := q.Get("format")
	stamp := time.Now().UTC().Format("20060102T150405Z")

	if format == "json" {
		events, err := s.collectAudit(r, filter)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"peek-audit-%s.json\"", stamp))
		writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
		return
	}

	events, err := s.collectAudit(r, filter)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"peek-audit-%s.csv\"", stamp))

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"at", "event", "secret_id", "user_id", "ip", "user_agent", "detail"})
	for _, e := range events {
		detail := ""
		for k, v := range e.Detail {
			if detail != "" {
				detail += "; "
			}
			detail += k + "=" + v
		}
		_ = cw.Write([]string{
			e.At.UTC().Format(time.RFC3339), e.Event, e.SecretID, e.UserID, e.IP, e.UserAgent, detail,
		})
	}
	cw.Flush()
}

// collectAudit pages through the trail so an export is not capped at one page.
func (s *Server) collectAudit(r *http.Request, filter store.AuditFilter) ([]store.AuditEvent, error) {
	const maxRows = 50000
	var out []store.AuditEvent
	for len(out) < maxRows {
		filter.Offset = len(out)
		page, err := s.store.ListAudit(r.Context(), filter)
		if err != nil {
			s.log.Error("audit export", "error", err.Error())
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		out = append(out, page...)
		if len(page) < filter.Limit {
			break
		}
	}
	return out, nil
}

func displayName(u store.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
