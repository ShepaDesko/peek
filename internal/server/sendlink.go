package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/store"
)

// Sending a link by e-mail.
//
// This is the one feature that bends the zero-knowledge property, and it does
// so openly. The link carries the key in its fragment, so e-mailing it means
// handing that key to this server for the moment it takes to send, and to
// every mail system between here and the recipient.
//
// Peek therefore:
//   - never stores the link or the key,
//   - never sends the passphrase, so a passphrase-protected secret stays
//     protected even if the mailbox is read,
//   - records that a message was sent, never what was in it,
//   - and the interface says all of this before the button is pressed.
//
// An instance that does not want the trade-off leaves mail.host empty: the
// endpoint then refuses and the interface does not offer it.

type sendLinkRequest struct {
	// Link is assembled by the browser and includes the key fragment.
	Link string `json:"link"`
	To   string `json:"to"`
	// Message is the sender's note, in the clear: it travels by e-mail.
	Message string `json:"message"`
	// HasPassphrase lets the message say one is needed, without saying what.
	HasPassphrase bool `json:"has_passphrase"`
}

func (s *Server) handleSendLink(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !pcrypto.ValidID(id) {
		notFound(w, r)
		return
	}
	if !s.mailer.Configured() {
		writeError(w, r, http.StatusServiceUnavailable, "mail_disabled",
			"This instance has no SMTP server configured, so it cannot send e-mail. Copy the link and send it yourself.")
		return
	}

	var req sendLinkRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	to := strings.TrimSpace(req.To)
	if !strings.Contains(to, "@") || len(to) > 320 {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_request", "That is not an e-mail address.", "to")
		return
	}
	if err := s.checkRecipientDomain(to); err != nil {
		writeFieldError(w, http.StatusForbidden, "forbidden", err.Error(), "to")
		return
	}

	// The link must point at this instance and at this secret: an open
	// redirect in an e-mail Peek signs its own name to would be a gift to a
	// phisher.
	if err := s.validateSecretLink(req.Link, id); err != nil {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_request", err.Error(), "link")
		return
	}

	// The metadata call also proves the secret exists and is still live,
	// without consuming anything.
	if _, err := s.secrets.Meta(r.Context(), id); err != nil {
		notFound(w, r)
		return
	}

	if err := s.mailSecretLink(r.Context(), to, req.Link, strings.TrimSpace(req.Message), req.HasPassphrase); err != nil {
		s.log.Error("send secret link", "error", err.Error())
		writeError(w, r, http.StatusBadGateway, "mail_failed",
			"The message could not be sent. Copy the link and send it yourself.")
		return
	}

	// The audit entry records that a message went out and to which domain —
	// never the link, and never the address in full.
	s.audit(r, store.AuditEvent{
		SecretID: id,
		Event:    store.EventLinkEmailed,
		Detail:   map[string]string{"domain": domainOf(to)},
	})
	writeJSON(w, http.StatusAccepted, map[string]any{"sent": true})
}

// validateSecretLink checks the link belongs to this instance and this secret.
func (s *Server) validateSecretLink(link, id string) error {
	if link == "" {
		return errMalformedLink
	}
	parsed, err := url.Parse(link)
	if err != nil {
		return errMalformedLink
	}
	public, err := url.Parse(s.cfg.PublicURL)
	if err != nil {
		return errMalformedLink
	}
	if !strings.EqualFold(parsed.Host, public.Host) || parsed.Scheme != public.Scheme {
		return errWrongHost
	}
	if parsed.Path != "/s/"+id {
		return errWrongSecret
	}
	if parsed.Fragment == "" {
		return errNoKey
	}
	return nil
}

func (s *Server) checkRecipientDomain(address string) error {
	allowed := s.cfg.Mail.AllowedDomains
	if len(allowed) == 0 {
		return nil
	}
	domain := domainOf(address)
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), domain) {
			return nil
		}
	}
	return errDomainNotAllowed
}

func domainOf(address string) string {
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(address[at+1:])
}

// Errors the link check can produce, worded for the person who sees them.
var (
	errMalformedLink    = errorString("that link is not readable")
	errWrongHost        = errorString("that link does not point at this instance")
	errWrongSecret      = errorString("that link is for a different secret")
	errNoKey            = errorString("that link carries no key, so it would be useless")
	errDomainNotAllowed = errorString("this instance does not send e-mail to that domain")
)

// errorString is a constant error without a package-level sentinel ceremony.
type errorString string

func (e errorString) Error() string { return string(e) }
