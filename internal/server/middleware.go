package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ShepaDesko/peek/internal/store"
)

type ctxKey string

const (
	ctxClientIP  ctxKey = "peek.client_ip"
	ctxRequestID ctxKey = "peek.request_id"
	ctxListener  ctxKey = "peek.listener"
)

// ClientIP returns the resolved client IP stored by the middleware.
func ClientIP(ctx context.Context) string {
	v, _ := ctx.Value(ctxClientIP).(string)
	return v
}

// RequestID returns the per-request identifier used in logs.
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

// ListenerName returns "public" or "internal" for the listener that accepted
// the request.
func ListenerName(ctx context.Context) string {
	v, _ := ctx.Value(ctxListener).(string)
	return v
}

func newRequestID() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return "0"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// withContext resolves the client IP once per request and tags the listener.
func (s *Server) withContext(listener string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxClientIP, s.trusted.ClientIP(r))
			ctx = context.WithValue(ctx, ctxRequestID, newRequestID())
			ctx = context.WithValue(ctx, ctxListener, listener)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// securityHeaders applies the hardening from section 5.3 of the spec.
//
// The CSP has no script-src 'unsafe-inline' and no external origin at all:
// everything the browser loads is served by this binary, so a compromised CDN
// or an injected tag cannot run. no-referrer keeps the key fragment out of
// outgoing requests even on a page the recipient navigates away from.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'self'",
		// 'wasm-unsafe-eval' is required for the Argon2id WebAssembly module
		// that derives the passphrase key in the browser. It permits
		// WebAssembly compilation only: it does not allow eval() or any
		// inline script, which is why it is not 'unsafe-eval'.
		"script-src 'self' 'wasm-unsafe-eval'",
		"style-src 'self'",
		"img-src 'self' data: blob:",
		"font-src 'self'",
		"connect-src 'self'",
		"media-src 'self' blob:",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"manifest-src 'self'",
	}, "; ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		if s.cfg.TLS.HSTS && s.trusted.Scheme(r) == "https" {
			h.Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", s.cfg.TLS.HSTSMaxAge))
		}
		next.ServeHTTP(w, r)
	})
}

// noStore marks everything that touches a secret as uncacheable.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// recoverer turns a panic into a 500 without leaking the stack to the client.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic serving request",
					"request_id", RequestID(r.Context()),
					"method", r.Method,
					"route", routePattern(r),
					"panic", fmt.Sprint(rec),
					"stack", string(debug.Stack()))
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// accessLog logs one line per request. It deliberately logs the route pattern
// and never the URL: a path such as /s/<id> is a secret identifier, and a
// fragment must never reach a log file at all.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		s.log.Info("request",
			"request_id", RequestID(r.Context()),
			"listener", ListenerName(r.Context()),
			"method", r.Method,
			"route", routePattern(r),
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", s.logIP(ClientIP(r.Context())),
		)
	})
}

// logIP applies the configured IP anonymisation to log output.
func (s *Server) logIP(ip string) string {
	if ip == "" {
		return ""
	}
	if s.cfg.Security.AnonymizeIPs {
		return store.AnonymizeIP(ip)
	}
	return ip
}

// limitBody caps the request body, after which the handler sees an error
// instead of reading forever.
func limitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit applies a token bucket keyed on the real client IP.
func (s *Server) rateLimit(l *Limiter, event string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r.Context())
			if !l.Allow(ip) {
				s.audit(r, store.AuditEvent{Event: store.EventRateLimited, Detail: map[string]string{"class": event}})
				w.Header().Set("Retry-After", strconv.Itoa(l.RetryAfter()))
				writeError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests. Please try again later.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// restrictCIDR gates a route on the real client IP. An empty list allows
// everyone, which is the documented default for a LAN-only instance.
func (s *Server) restrictCIDR(allowed []*net.IPNet, what string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowed) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			ip := net.ParseIP(ClientIP(r.Context()))
			for _, n := range allowed {
				if ip != nil && n.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}
			s.audit(r, store.AuditEvent{Event: store.EventAdminBlocked, Detail: map[string]string{"area": what}})
			// 404, not 403: an unauthorised network learns nothing about what
			// exists behind the gate.
			writeError(w, r, http.StatusNotFound, "not_found", "Not found.")
		})
	}
}

// publicOnly rejects internal-only routes when they are reached through the
// public listener. The route table already separates them; this is the second
// lock, so a routing mistake cannot expose the admin surface.
func (s *Server) internalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ListenerName(r.Context()) == listenerPublic {
			s.audit(r, store.AuditEvent{Event: store.EventAdminBlocked, Detail: map[string]string{"area": "public_listener"}})
			writeError(w, r, http.StatusNotFound, "not_found", "Not found.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func routePattern(r *http.Request) string {
	if rc := chiRouteContext(r); rc != "" {
		return rc
	}
	return "unmatched"
}
