package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/branding"
	"github.com/ShepaDesko/peek/internal/mail"
	"github.com/ShepaDesko/peek/internal/store"
)

// The brand: what every visitor is served, and what an administrator edits.

// languages are the languages this build ships an interface in.
var languages = []string{"fr", "en"}

// theme resolves the brand for a request: peek.toml, with whatever was saved
// in the database layered on top.
//
// A database that cannot be read is not a reason to serve an unbranded page,
// so a failure here falls back to the configured brand and is logged.
func (s *Server) theme(r *http.Request) branding.Resolved {
	orgID := s.orgOf(r)
	var stored *store.Branding
	if saved, err := s.store.Branding(r.Context(), orgID); err == nil {
		stored = &saved
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Error("cannot read the stored brand", "error", err.Error())
	}
	assets, err := s.store.ListAssets(r.Context(), orgID)
	if err != nil {
		s.log.Error("cannot list the brand assets", "error", err.Error())
	}
	return branding.Resolve(s.cfg, stored, assets, languages)
}

// handleBranding serves the resolved theme as JSON. The interface fetches it
// before first paint, which is how an instance can be rebranded without
// rebuilding or restarting anything.
func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) {
	theme := s.theme(r)
	etag := theme.ETag()
	w.Header().Set("ETag", etag)
	// The theme is not a secret, so it may be revalidated rather than refetched.
	w.Header().Set("Cache-Control", "no-cache, private")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, theme)
}

// handleBrandingCSS serves the theme as a stylesheet of custom properties,
// plus the administrator's own CSS. Serving it as a file rather than an inline
// block is what lets the CSP keep style-src 'self' with no unsafe-inline.
func (s *Server) handleBrandingCSS(w http.ResponseWriter, r *http.Request) {
	theme := s.theme(r)
	custom := ""
	if saved, err := s.store.Branding(r.Context(), s.orgOf(r)); err == nil {
		custom = saved.CustomCSS
	}

	etag := theme.ETag()
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache, private")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	// The body is a stylesheet, served with a CSS content type and built from
	// values CheckCSS accepted at save time; nothing here is interpolated into
	// HTML. gosec cannot see that, so the reason is written down instead.
	_, _ = w.Write([]byte(theme.CSS(custom))) //nolint:gosec // G705: a text/css body, sanitised on the way in
}

// handleBrandingAsset serves a logo, a favicon or the Open Graph image.
//
// The URL carries the asset digest, so the response is immutable for a year
// and a changed logo appears immediately under its new URL.
func (s *Server) handleBrandingAsset(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if !store.ValidAssetKind(kind) {
		notFound(w, r)
		return
	}
	asset, err := s.store.Asset(r.Context(), s.orgOf(r), kind)
	if err != nil {
		notFound(w, r)
		return
	}

	etag := `"` + asset.ETag + `"`
	w.Header().Set("ETag", etag)
	if r.URL.Query().Get("v") == asset.ETag {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	// An SVG is served from our own origin, so it is sandboxed as tightly as
	// the rest: it was checked on upload, and this header stops a direct hit
	// on the file from running anything.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", asset.ContentType)
	http.ServeContent(w, r, kind, asset.UpdatedAt, strings.NewReader(string(asset.Bytes)))
}

// --- administration ----------------------------------------------------------

type brandingRequest struct {
	ServiceName     string                       `json:"service_name"`
	PrimaryColor    string                       `json:"primary_color"`
	AccentColor     string                       `json:"accent_color"`
	BackgroundColor string                       `json:"background_color"`
	CornerRadius    string                       `json:"corner_radius"`
	Font            string                       `json:"font"`
	ButtonStyle     string                       `json:"button_style"`
	HidePoweredBy   bool                         `json:"hide_powered_by"`
	SupportURL      string                       `json:"support_url"`
	LegalURL        string                       `json:"legal_url"`
	PrivacyURL      string                       `json:"privacy_url"`
	ContactEmail    string                       `json:"contact_email"`
	Texts           map[string]map[string]string `json:"texts"`
	CustomCSS       string                       `json:"custom_css"`
}

// handleBrandingOptions tells the customisation page what it may offer: the
// fonts, the corner presets, the button styles, the text keys and the
// languages this build ships.
func (s *Server) handleBrandingOptions(w http.ResponseWriter, r *http.Request) {
	stored, err := s.store.Branding(r.Context(), s.orgOf(r))
	saved := err == nil

	assets, _ := s.store.ListAssets(r.Context(), s.orgOf(r))
	assetInfo := make([]map[string]any, 0, len(assets))
	for _, a := range assets {
		assetInfo = append(assetInfo, map[string]any{
			"kind":         a.Kind,
			"content_type": a.ContentType,
			"size_bytes":   a.SizeBytes,
			"url":          "/branding/" + a.Kind + "?v=" + a.ETag,
			"updated_at":   a.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"theme":      s.theme(r),
		"saved":      saved,
		"custom_css": stored.CustomCSS,
		"texts":      branding.ParseTexts(stored.Texts, languages),
		"assets":     assetInfo,
		"options": map[string]any{
			"fonts":           branding.Fonts,
			"radii":           branding.Radii,
			"button_styles":   branding.ButtonStyles,
			"text_keys":       branding.TextKeys,
			"languages":       languages,
			"asset_kinds":     store.AssetKinds,
			"max_css_bytes":   branding.MaxCustomCSSBytes,
			"max_asset_bytes": branding.MaxAssetBytes,
		},
		"mail_configured": s.mailer.Configured(),
	})
}

func (s *Server) handleSaveBranding(w http.ResponseWriter, r *http.Request) {
	var req brandingRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	p := principalOf(r.Context())

	css, err := branding.CheckCSS(req.CustomCSS)
	if err != nil {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_css", err.Error(), "custom_css")
		return
	}
	texts, err := branding.MarshalTexts(branding.Texts(req.Texts), languages)
	if err != nil {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_texts", err.Error(), "texts")
		return
	}
	for field, value := range map[string]string{
		"support_url": req.SupportURL,
		"legal_url":   req.LegalURL,
		"privacy_url": req.PrivacyURL,
	} {
		if err := checkLinkURL(value); err != nil {
			writeFieldError(w, http.StatusUnprocessableEntity, "bad_url", err.Error(), field)
			return
		}
	}

	saved, err := s.store.SaveBranding(r.Context(), store.Branding{
		OrgID:           s.orgOf(r),
		ServiceName:     strings.TrimSpace(req.ServiceName),
		PrimaryColor:    strings.TrimSpace(req.PrimaryColor),
		AccentColor:     strings.TrimSpace(req.AccentColor),
		BackgroundColor: strings.TrimSpace(req.BackgroundColor),
		CornerRadius:    strings.TrimSpace(req.CornerRadius),
		Font:            strings.TrimSpace(req.Font),
		ButtonStyle:     strings.TrimSpace(req.ButtonStyle),
		HidePoweredBy:   req.HidePoweredBy,
		SupportURL:      strings.TrimSpace(req.SupportURL),
		LegalURL:        strings.TrimSpace(req.LegalURL),
		PrivacyURL:      strings.TrimSpace(req.PrivacyURL),
		ContactEmail:    strings.TrimSpace(req.ContactEmail),
		Texts:           texts,
		CustomCSS:       css,
		UpdatedBy:       p.User.ID,
	})
	if err != nil {
		s.log.Error("save branding", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}

	s.audit(r, store.AuditEvent{
		UserID: p.User.ID,
		Event:  store.EventBrandingChanged,
		Detail: map[string]string{"version": strconv.Itoa(saved.Version)},
	})
	assets, _ := s.store.ListAssets(r.Context(), s.orgOf(r))
	writeJSON(w, http.StatusOK, branding.Resolve(s.cfg, &saved, assets, languages))
}

func (s *Server) handleResetBranding(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r.Context())
	if err := s.store.ResetBranding(r.Context(), s.orgOf(r)); err != nil {
		s.log.Error("reset branding", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventBrandingReset})
	writeJSON(w, http.StatusOK, s.theme(r))
}

// handleUploadAsset stores a logo, favicon, background or Open Graph image.
//
// The body is the raw image rather than a multipart form: there is exactly one
// file, the interface sends it with fetch, and a multipart parser is a larger
// attack surface than a byte slice.
func (s *Server) handleUploadAsset(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if !store.ValidAssetKind(kind) {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_request", "Unknown image kind.", "kind")
		return
	}
	p := principalOf(r.Context())

	data, err := io.ReadAll(io.LimitReader(r.Body, branding.MaxAssetBytes+1))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", "Could not read the image.")
		return
	}
	contentType, err := branding.ValidateAsset(kind, data)
	if err != nil {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_image", err.Error(), "file")
		return
	}

	if err := s.store.SaveAsset(r.Context(), store.BrandingAsset{
		OrgID:       s.orgOf(r),
		Kind:        kind,
		ContentType: contentType,
		Bytes:       data,
		ETag:        branding.AssetETag(data),
	}); err != nil {
		s.log.Error("save branding asset", "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	// The brand version changes too, so every cached theme is revalidated.
	if saved, err := s.store.Branding(r.Context(), s.orgOf(r)); err == nil {
		if _, err := s.store.SaveBranding(r.Context(), saved); err != nil {
			s.log.Error("bump branding version", "error", err.Error())
		}
	}

	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventBrandingChanged,
		Detail: map[string]string{"asset": kind, "content_type": contentType}})
	writeJSON(w, http.StatusCreated, map[string]any{
		"kind":         kind,
		"content_type": contentType,
		"size_bytes":   len(data),
		"url":          "/branding/" + kind + "?v=" + branding.AssetETag(data),
	})
}

func (s *Server) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	p := principalOf(r.Context())
	if err := s.store.DeleteAsset(r.Context(), s.orgOf(r), kind); err != nil {
		notFound(w, r)
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventBrandingChanged,
		Detail: map[string]string{"asset_removed": kind}})
	w.WriteHeader(http.StatusNoContent)
}

type testEmailRequest struct {
	To string `json:"to"`
}

// handleTestEmail sends one message to prove the SMTP settings work.
func (s *Server) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	var req testEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !s.mailer.Configured() {
		writeError(w, r, http.StatusServiceUnavailable, "mail_disabled",
			"This instance has no SMTP server configured. Set the [mail] block in peek.toml.")
		return
	}
	p := principalOf(r.Context())
	to := strings.TrimSpace(req.To)
	if to == "" {
		to = p.User.Email
	}
	if !strings.Contains(to, "@") {
		writeFieldError(w, http.StatusUnprocessableEntity, "bad_request", "That is not an e-mail address.", "to")
		return
	}

	theme := s.theme(r)
	body := mail.Message{
		To:      []string{to},
		Subject: "Test — " + theme.ServiceName,
		Text: "Ceci est un message de test envoyé depuis " + theme.ServiceName + ".\n\n" +
			"Si vous le recevez, la configuration SMTP de l'instance fonctionne.\n",
		HTML: s.brandedHTML(theme,
			"Message de test",
			"Si vous recevez ce message, la configuration SMTP de l'instance fonctionne.",
			"", "", ""),
	}
	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()
	if err := s.mailer.Send(ctx, body); err != nil {
		s.log.Error("send test e-mail", "error", err.Error())
		writeError(w, r, http.StatusBadGateway, "mail_failed", err.Error())
		return
	}
	s.audit(r, store.AuditEvent{UserID: p.User.ID, Event: store.EventTestEmailSent,
		Detail: map[string]string{"domain": domainOf(to)}})
	writeJSON(w, http.StatusAccepted, map[string]any{"sent": true, "to": to})
}

// checkLinkURL refuses a footer link that is not http(s): a javascript: link
// in the footer of every page would be a stored cross-site script.
func checkLinkURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return errors.New("a link must start with http:// or https://")
	}
	if len(value) > 2048 {
		return errors.New("that link is too long")
	}
	return nil
}
