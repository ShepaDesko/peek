package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/orgs"
	"github.com/ShepaDesko/peek/internal/store"
)

// The platform surface: organisations and their domains.
//
// Every route here needs the platform_admin role and a session. A role above
// admin exists for exactly this: on a hosted instance, the person who creates
// a customer is not the person who administers that customer, and an
// administrator of one organisation must not be able to see the others exist.
//
// None of it is reachable on a single-tenant instance — the service answers
// ErrNotMultiOrg, which becomes a 409 naming the setting to change.

type createOrgRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type updateOrgRequest struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type addDomainRequest struct {
	Domain string `json:"domain"`
}

func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	list, err := s.orgs.List(r.Context())
	if err != nil {
		s.log.Error("list organisations", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	if list == nil {
		list = []orgs.Listed{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"multi_org": s.orgs.MultiOrg(),
		"orgs":      list,
	})
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req createOrgRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	org, err := s.orgs.Create(r.Context(), req.Slug, req.Name)
	if err != nil {
		s.writeOrgError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{
		UserID: principalOf(r.Context()).User.ID,
		Event:  store.EventOrgCreated,
		Detail: map[string]string{"org": org.ID, "slug": org.Slug},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"org": org})
}

func (s *Server) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	var req updateOrgRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.orgs.Update(r.Context(), id, req.Name, req.Status); err != nil {
		s.writeOrgError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{
		UserID: principalOf(r.Context()).User.ID,
		Event:  store.EventOrgUpdated,
		Detail: map[string]string{"org": id, "status": req.Status},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.orgs.Delete(r.Context(), id); err != nil {
		s.writeOrgError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{
		UserID: principalOf(r.Context()).User.ID,
		Event:  store.EventOrgDeleted,
		Detail: map[string]string{"org": id},
	})
	w.WriteHeader(http.StatusNoContent)
}

// --- domains ----------------------------------------------------------------

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	list, err := s.orgs.ListDomains(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.log.Error("list domains", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	if list == nil {
		list = []store.Domain{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": list, "record": domainRecipe(list)})
}

// handleAddDomain declares a domain and answers with the record to publish.
//
// The response carries the exact DNS name and value: an operator should be
// able to paste them into a zone file without reading the documentation, and
// the most common cause of a failed verification is a value typed from memory.
func (s *Server) handleAddDomain(w http.ResponseWriter, r *http.Request) {
	var req addDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	orgID := chi.URLParam(r, "id")
	domain, err := s.orgs.AddDomain(r.Context(), orgID, req.Domain)
	if err != nil {
		s.writeOrgError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{
		UserID: principalOf(r.Context()).User.ID,
		Event:  store.EventDomainAdded,
		Detail: map[string]string{"org": orgID, "domain": domain.Domain},
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"domain": domain,
		"record": map[string]string{
			"type":  "TXT",
			"name":  orgs.RecordName(domain.Domain),
			"value": orgs.RecordValue(domain.Token),
		},
	})
}

// handleVerifyDomain performs the DNS lookup.
//
// This is the only outbound DNS query Peek ever makes, and it happens because
// an administrator pressed a button. It is not a background job and nothing is
// resolved on a recipient's request path, so an air-gapped instance simply
// never reaches this handler.
func (s *Server) handleVerifyDomain(w http.ResponseWriter, r *http.Request) {
	orgID, name := chi.URLParam(r, "id"), chi.URLParam(r, "domain")
	domain, err := s.orgs.Verify(r.Context(), name)
	ok := err == nil

	s.audit(r, store.AuditEvent{
		UserID: principalOf(r.Context()).User.ID,
		Event:  store.EventDomainChecked,
		Detail: map[string]string{"org": orgID, "domain": name, "verified": boolString(ok)},
	})

	if errors.Is(err, store.ErrNotFound) || errors.Is(err, orgs.ErrNotMultiOrg) {
		s.writeOrgError(w, r, err)
		return
	}
	if err != nil {
		// Not a 4xx: the call worked, the record is not there yet. The
		// distinction matters to whoever is waiting for DNS to propagate.
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false,
			"error":    err.Error(),
			"record": map[string]string{
				"type":  "TXT",
				"name":  orgs.RecordName(domain.Domain),
				"value": orgs.RecordValue(domain.Token),
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true, "domain": domain})
}

func (s *Server) handleSetPrimaryDomain(w http.ResponseWriter, r *http.Request) {
	orgID, name := chi.URLParam(r, "id"), chi.URLParam(r, "domain")
	if err := s.orgs.SetPrimary(r.Context(), orgID, name); err != nil {
		s.writeOrgError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	orgID, name := chi.URLParam(r, "id"), chi.URLParam(r, "domain")
	if err := s.orgs.RemoveDomain(r.Context(), orgID, name); err != nil {
		s.writeOrgError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{
		UserID: principalOf(r.Context()).User.ID,
		Event:  store.EventDomainRemoved,
		Detail: map[string]string{"org": orgID, "domain": name},
	})
	w.WriteHeader(http.StatusNoContent)
}

// domainRecipe returns the records still waiting to be published, so a listing
// is actionable on its own.
func domainRecipe(list []store.Domain) []map[string]string {
	var out []map[string]string
	for _, d := range list {
		if d.Verified() {
			continue
		}
		out = append(out, map[string]string{
			"domain": d.Domain,
			"type":   "TXT",
			"name":   orgs.RecordName(d.Domain),
			"value":  orgs.RecordValue(d.Token),
		})
	}
	return out
}

func (s *Server) writeOrgError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, orgs.ErrNotMultiOrg):
		writeError(w, r, http.StatusConflict, "single_tenant", err.Error())
	case errors.Is(err, store.ErrOrgExists):
		writeError(w, r, http.StatusConflict, "exists",
			"That slug or domain is already used on this instance.")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "No such organisation or domain.")
	case errors.Is(err, orgs.ErrUnverified):
		writeError(w, r, http.StatusConflict, "unverified", err.Error())
	case strings.Contains(err.Error(), "still has"), strings.Contains(err.Error(), "cannot be deleted"),
		strings.Contains(err.Error(), "is required"), strings.Contains(err.Error(), "is not a domain"),
		strings.Contains(err.Error(), "status must be"), strings.Contains(err.Error(), "unverified domain"),
		strings.Contains(err.Error(), "instance's own organisation"):
		// The service writes these for a human; passing them through is more
		// use than a generic 400.
		writeError(w, r, http.StatusConflict, "refused", err.Error())
	default:
		s.log.Error("organisation operation", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
	}
}
