package server

import (
	"net/http"

	"github.com/ShepaDesko/peek/internal/branding"
)

// handleBranding serves the resolved theme as JSON. The interface fetches it
// before first paint, which is how an instance can be rebranded without
// rebuilding anything.
func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) {
	theme := branding.FromConfig(s.cfg)
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

// handleBrandingCSS serves the theme as a stylesheet of CSS custom properties.
func (s *Server) handleBrandingCSS(w http.ResponseWriter, r *http.Request) {
	theme := branding.FromConfig(s.cfg)
	etag := theme.ETag()
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache, private")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write([]byte(theme.CSS()))
}
