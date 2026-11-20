// Package webui embeds the compiled single-page application into the binary.
//
// This is what makes Peek a single file: no node_modules, no asset directory
// to deploy, nothing loaded from the internet at runtime. The build copies
// web/dist here (see the Makefile target web-build).
package webui

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// Handler serves the SPA: hashed assets with a long cache, everything else
// falling back to index.html so client-side routes work on a hard refresh.
type Handler struct {
	files fs.FS
	index []byte
	// Built reports whether a real build is embedded rather than the
	// placeholder committed to keep go build working without Node.
	Built bool
}

// placeholder is served when the binary was built without running the
// frontend build. The API, /healthz and /readyz all still work, which is what
// a Go-only contributor needs.
const placeholder = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>Peek</title></head>
<body><main><h1>Peek</h1>
<p>Interface non compilée. Lancez <code>make web-build</code> puis reconstruisez le binaire.</p>
<p>L'API reste disponible sur <code>/api/v1</code>, ainsi que <code>/healthz</code> et <code>/readyz</code>.</p>
</main></body></html>
`

// NewHandler prepares the embedded file system.
func NewHandler() (*Handler, error) {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return &Handler{files: sub, index: []byte(placeholder), Built: false}, nil
	}
	h := &Handler{files: sub, index: index}
	if _, err := fs.Stat(sub, "assets"); err == nil {
		h.Built = true
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clean := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	name := strings.TrimPrefix(clean, "/")

	if name != "" {
		if f, err := h.files.Open(name); err == nil {
			defer func() { _ = f.Close() }()
			if info, err := f.Stat(); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// Vite emits content-hashed names under assets/.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				//nolint:errcheck // the type assertion is guarded by the fs.File contract
				http.ServeContent(w, r, info.Name(), info.ModTime(), f.(interface {
					Read([]byte) (int, error)
					Seek(int64, int) (int64, error)
				}))
				return
			}
		}
	}

	// Unknown path: hand over the application shell. A secret page is never
	// cached, so the shell is not either.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.index)
}
