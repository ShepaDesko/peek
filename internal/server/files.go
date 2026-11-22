package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/store"
)

// File upload and download.
//
// Uploads go to the internal listener, behind the same gate as creation: a
// public instance is not an open file drop. Downloads are recipient-facing and
// therefore live on both listeners, but need a grant issued by a successful
// reveal — proving possession of the read token once is what opens the blobs.
//
// Neither direction ever logs an identifier: the access log records the route
// pattern, and a file id is a secret identifier like any other.

// downloadTokenHeader carries the grant. It is a header and not a query
// parameter on purpose: a proxy logs URLs, and a grant in a URL would end up
// in somebody's access log.
const downloadTokenHeader = "X-Peek-Download" //nolint:gosec // a header name, not a credential

func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if p == nil && !s.cfg.Security.AnonymousCreate {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated",
			"Sign in to send a file, or enable security.anonymous_create in peek.toml.")
		return
	}
	if p != nil && p.User.Role == store.RoleAuditor {
		writeError(w, r, http.StatusForbidden, "forbidden", "An auditor account cannot send files.")
		return
	}
	if s.blobs == nil {
		writeError(w, r, http.StatusServiceUnavailable, "no_storage",
			"This instance has no file storage configured.")
		return
	}

	creatorID, orgID := "", store.DefaultOrgID
	if p != nil {
		creatorID, orgID = p.User.ID, p.User.OrgID
	}

	// The length has to be known up front: the storage backend writes exactly
	// that many bytes, and S3 needs it to sign a non-chunked PUT.
	size := r.ContentLength
	if size < 0 {
		writeFieldError(w, http.StatusLengthRequired, "length_required",
			"Send the file with a Content-Length: a chunked upload cannot be checked against the size limit.", "size")
		return
	}
	if max := s.secrets.MaxUploadBytes(); max > 0 && size > max {
		writeFieldError(w, http.StatusRequestEntityTooLarge, "too_large",
			"This file is larger than the instance allows.", "size")
		return
	}

	// The global body limit is sized for JSON; an upload gets its own, taken
	// from the policy rather than from server.max_body_bytes.
	body := io.Reader(r.Body)
	if max := s.secrets.MaxUploadBytes(); max > 0 {
		body = http.MaxBytesReader(w, r.Body, max)
	}

	up, err := s.secrets.AcceptUpload(r.Context(), orgID, creatorID, size, body)
	switch {
	case err == nil:
	case errors.Is(err, secrets.ErrNoStorage):
		writeError(w, r, http.StatusServiceUnavailable, "no_storage",
			"This instance has no file storage configured.")
		return
	case errors.Is(err, secrets.ErrTooLarge):
		writeFieldError(w, http.StatusRequestEntityTooLarge, "too_large",
			"This file is larger than the instance allows.", "size")
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
		s.log.Error("accept upload", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	s.audit(r, store.AuditEvent{
		OrgID:  orgID,
		UserID: creatorID,
		Event:  store.EventFileUploaded,
		Detail: map[string]string{"size_bytes": strconv.FormatInt(up.Size, 10)},
	})
	writeJSON(w, http.StatusCreated, up)
}

func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	raw := r.Header.Get(downloadTokenHeader)
	if raw == "" {
		notFound(w, r)
		return
	}
	token, err := pcrypto.B64.DecodeString(raw)
	if err != nil || len(token) != 32 {
		notFound(w, r)
		return
	}

	rc, size, err := s.secrets.OpenDownload(r.Context(), token, id)
	switch {
	case err == nil:
	case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrNoStorage):
		notFound(w, r)
		return
	default:
		s.log.Error("download file", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	defer func() { _ = rc.Close() }()

	// The bytes are ciphertext and the name is inside the sealed payload, so
	// there is nothing to say here but "opaque data, do not sniff it".
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, rc); err != nil {
		// The client went away mid-download, or storage failed halfway. The
		// response is already committed, so there is nothing to say to them.
		s.log.Warn("file download interrupted", "error", err.Error())
	}
}
