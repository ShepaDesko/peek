// Package server assembles the HTTP surface: routing, hardening middleware,
// the two listeners and graceful shutdown.
//
// The route table is split in two. The public mux carries only what a
// recipient needs; the internal mux carries everything. An instance that sets
// server.public_listen publishes the first one to the load balancer and keeps
// creation, the dashboard, administration and the API on the LAN.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ShepaDesko/peek/internal/accounts"
	"github.com/ShepaDesko/peek/internal/audit"
	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/mail"
	"github.com/ShepaDesko/peek/internal/oidc"
	"github.com/ShepaDesko/peek/internal/requests"
	"github.com/ShepaDesko/peek/internal/secrets"
	"github.com/ShepaDesko/peek/internal/storage"
	"github.com/ShepaDesko/peek/internal/store"
	"github.com/ShepaDesko/peek/internal/webhooks"
	"github.com/ShepaDesko/peek/internal/webui"
)

const (
	listenerPublic   = "public"
	listenerInternal = "internal"
)

// Server owns the HTTP listeners and the handlers behind them.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	store    *store.Store
	secrets  *secrets.Service
	requests *requests.Service
	blobs    storage.Backend
	trusted  *TrustedProxies

	adminCIDRs  []*net.IPNet
	createCIDRs []*net.IPNet

	limitCreate RateLimiter
	limitRead   RateLimiter
	limitLogin  RateLimiter
	limitAPI    RateLimiter

	accounts *accounts.Service
	mailer   mail.Sender
	siem     audit.Forwarder
	hooks    *webhooks.Deliverer
	sso      *oidc.Provider
	cipher   *pcrypto.ServerCipher

	ui      *webui.Handler
	version string
	started time.Time

	mu        sync.Mutex
	servers   []*http.Server
	listeners []net.Listener
}

// Options configure New.
type Options struct {
	Config  *config.Config
	Logger  *slog.Logger
	Store   *store.Store
	Version string
	// Cipher encrypts server-side metadata (TOTP seeds, credentials). It may
	// be nil on an instance with no master key; the features that need it
	// then refuse with a clear message instead of starting half-working.
	Cipher *pcrypto.ServerCipher
	// Mailer is optional: without one, nothing is e-mailed and the interface
	// hands over links directly.
	Mailer mail.Sender
	// SIEM forwards the audit trail; nil means the database copy only.
	SIEM audit.Forwarder
	// Blobs stores encrypted attachments. Without one, file secrets are
	// refused with a clear message rather than quietly dropped.
	Blobs storage.Backend
	// Webhooks sends the queued deliveries. The server only needs it to send
	// a test ping; the queue itself is drained by the background job.
	Webhooks *webhooks.Deliverer
}

// New builds a Server. It fails rather than start with a configuration whose
// network trust cannot be parsed.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("server: missing configuration")
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	trusted, err := NewTrustedProxies(opts.Config.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("server.trusted_proxies: %w", err)
	}
	adminCIDRs, err := parseCIDRs(opts.Config.Security.AdminAllowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("security.admin_allowed_cidrs: %w", err)
	}
	createCIDRs, err := parseCIDRs(opts.Config.Security.CreateAllowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("security.create_allowed_cidrs: %w", err)
	}
	ui, err := webui.NewHandler()
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:         opts.Config,
		log:         log,
		store:       opts.Store,
		secrets:     secrets.New(opts.Store, opts.Config),
		trusted:     trusted,
		adminCIDRs:  adminCIDRs,
		createCIDRs: createCIDRs,
		limitCreate: newLimiter(opts.Store, log, opts.Config, "create", opts.Config.Security.RateCreate),
		limitRead:   newLimiter(opts.Store, log, opts.Config, "read", opts.Config.Security.RateRead),
		limitLogin:  newLimiter(opts.Store, log, opts.Config, "login", opts.Config.Security.RateLogin),
		limitAPI:    newLimiter(opts.Store, log, opts.Config, "api", opts.Config.Security.RateAPI),
		ui:          ui,
		version:     opts.Version,
		started:     time.Now(),
	}
	s.secrets.SetStorage(opts.Blobs)
	s.blobs = opts.Blobs
	s.requests = requests.New(opts.Store, opts.Config, s.secrets)
	s.accounts = accounts.New(opts.Store, opts.Config, opts.Cipher)
	s.cipher = opts.Cipher
	s.mailer = opts.Mailer
	if s.mailer == nil {
		s.mailer = mail.Discard{Log: log}
	}
	s.siem = opts.SIEM
	if s.siem == nil {
		s.siem = audit.Nop{}
	}
	// A configured webhook fires because it is configured, not because a
	// caller remembered to wire the dispatcher in. Queueing is attached here,
	// in the one place that also writes the audit trail, so no entry point can
	// end up with endpoints in peek.toml and a queue that stays empty.
	if dispatcher := webhooks.NewDispatcher(opts.Config, opts.Store, log); dispatcher.Enabled() {
		s.siem = audit.Multi{s.siem, dispatcher}
	}
	// Single sign-on, like the webhook dispatcher, is built from the
	// configuration rather than handed in: configured means enabled.
	provider, err := oidc.New(opts.Config.SSO, log)
	if err != nil {
		return nil, err
	}
	s.sso = provider
	s.hooks = opts.Webhooks
	if s.hooks == nil {
		// A nil deliverer is a valid one: Enabled reports false and the
		// webhook routes answer "nothing is configured".
		s.hooks, _ = webhooks.NewDeliverer(opts.Config, opts.Store, log, opts.Version)
	}
	return s, nil
}

// Accounts exposes the account service, for the CLI and the tests.
func (s *Server) Accounts() *accounts.Service { return s.accounts }

// Secrets exposes the service, for tests and the CLI.
func (s *Server) Secrets() *secrets.Service { return s.secrets }

// Requests exposes the secret-request service, for tests and the CLI.
func (s *Server) Requests() *requests.Service { return s.requests }

// Handler returns the handler for one listener role.
func (s *Server) Handler(listener string) http.Handler {
	r := chi.NewRouter()
	r.Use(s.withContext(listener))
	r.Use(s.recoverer)
	r.Use(s.accessLog)
	r.Use(s.securityHeaders)
	r.Use(limitBody(s.cfg.Server.MaxBodyBytes))

	// Health checks are intentionally unauthenticated, tiny and cacheless, so
	// a load balancer can poll them without learning anything.
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/robots.txt", s.handleRobots)

	r.Route("/api/v1", func(api chi.Router) {
		api.Use(noStore)
		// Every API route resolves the caller when a session cookie is
		// present; each group then decides whether it needs one.
		api.Use(s.withPrincipal)

		api.Get("/branding", s.handleBranding)
		api.Get("/ip", s.handleWhoami)

		// Recipient-facing routes: available on both listeners.
		api.Group(func(pub chi.Router) {
			pub.Use(s.rateLimit(s.limitRead, "read"))
			pub.Get("/secrets/{id}", s.handleSecretMeta)
			pub.Post("/secrets/{id}/reveal", s.handleReveal)
			pub.Delete("/secrets/{id}", s.handleRecipientDelete)

			// Attachments: readable only with a grant handed out by a
			// successful reveal, which is why they sit beside it.
			pub.Get("/files/{id}", s.handleDownloadFile)
			pub.Head("/files/{id}", s.handleDownloadFile)

			// Secret requests: reading the prompt and depositing an answer
			// are recipient-facing, so an instance can expose only those.
			pub.Get("/requests/{id}", s.handleRequestMeta)
			pub.Post("/requests/{id}/open", s.handleOpenRequest)
			pub.Post("/requests/{id}/deposit", s.handleDeposit)
		})

		// Everything below is internal-listener only.
		api.Group(func(priv chi.Router) {
			priv.Use(s.internalOnly)
			priv.Use(s.requireCSRF)

			// --- sign-in surface: rate limited, no session needed ----------
			priv.Group(func(anon chi.Router) {
				anon.Use(s.rateLimit(s.limitLogin, "login"))
				anon.Post("/auth/login", s.handleLogin)
				anon.Post("/auth/mfa", s.handleMFA)
				anon.Post("/auth/bootstrap", s.handleBootstrap)
				anon.Post("/auth/password/forgot", s.handleForgotPassword)
				anon.Post("/auth/password/reset", s.handleResetPassword)
				anon.Get("/auth/sso", s.handleSSOInfo)
				anon.Post("/auth/passkeys/login/start", s.handlePasskeyLoginStart)
				anon.Post("/auth/passkeys/login/finish", s.handlePasskeyLoginFinish)
				anon.Post("/invitations/preview", s.handlePreviewInvitation)
				anon.Post("/invitations/accept", s.handleAcceptInvitation)
			})

			priv.Group(func(open chi.Router) {
				open.Use(s.rateLimit(s.limitAPI, "api"))
				open.Get("/auth/me", s.handleMe)
				open.Post("/auth/logout", s.handleLogout)
				open.Get("/policy", s.handlePolicy)
				// The API describes itself, from its own route table.
				open.Get("/openapi.json", s.handleOpenAPI)
			})

			// --- creating and following your own secrets -------------------
			priv.Group(func(create chi.Router) {
				create.Use(s.restrictCIDR(s.createCIDRs, "create"))
				create.Use(s.rateLimit(s.limitCreate, "create"))
				create.Use(s.requireScope(store.ScopeSecretsWrite))
				create.Post("/secrets", s.handleCreate)
				create.Post("/requests", s.handleCreateRequest)
				// Uploading sits behind the creation gate, not the read one:
				// an instance that does not let you create a secret is not a
				// place to drop a hundred megabytes either.
				create.Post("/files", s.handleUploadFile)
			})
			priv.Group(func(sender chi.Router) {
				sender.Use(s.rateLimit(s.limitAPI, "api"))
				sender.Use(s.requireScope(store.ScopeSecretsManage))
				sender.Get("/secrets/{id}/receipt", s.handleReceipt)
				sender.Post("/secrets/{id}/burn", s.handleBurn)
				sender.Post("/secrets/{id}/email", s.handleSendLink)
				sender.Get("/requests/{id}/receipt", s.handleRequestReceipt)
				sender.Post("/requests/{id}/receipt", s.handleRequestReceipt)
				sender.Delete("/requests/{id}", s.handleCloseRequest)
			})

			// --- signed-in account management ------------------------------
			priv.Group(func(account chi.Router) {
				account.Use(s.rateLimit(s.limitAPI, "api"))
				account.Use(s.requireAuth)
				// The account surface changes credentials, sessions and
				// passkeys. A bearer token has no business there, and a token
				// that could mint tokens would turn one leak into a permanent
				// foothold.
				account.Use(s.requireSession)

				account.Get("/auth/tokens", s.handleListTokens)
				account.Post("/auth/tokens", s.handleCreateToken)
				account.Delete("/auth/tokens/{id}", s.handleRevokeToken)

				account.Post("/auth/password", s.handleChangePassword)
				account.Post("/auth/totp/start", s.handleTOTPStart)
				account.Post("/auth/totp/confirm", s.handleTOTPConfirm)
				account.Post("/auth/totp/disable", s.handleTOTPDisable)
				account.Post("/auth/recovery-codes", s.handleRecoveryCodes)

				account.Get("/auth/sessions", s.handleListSessions)
				account.Delete("/auth/sessions/{id}", s.handleRevokeSession)
				account.Post("/auth/sessions/revoke-others", s.handleRevokeOtherSessions)

				account.Get("/auth/passkeys", s.handleListPasskeys)
				account.Post("/auth/passkeys/register/start", s.handlePasskeyRegisterStart)
				account.Post("/auth/passkeys/register/finish", s.handlePasskeyRegisterFinish)
				account.Patch("/auth/passkeys/{id}", s.handleRenamePasskey)
				account.Delete("/auth/passkeys/{id}", s.handleDeletePasskey)

				account.Get("/dashboard/requests", s.handleListRequests)
				account.Get("/dashboard/secrets", s.handleDashboard)
				account.Post("/dashboard/secrets/{id}/burn", s.handleBurnOwned)
			})

			// --- administration --------------------------------------------
			priv.Group(func(admin chi.Router) {
				admin.Use(s.restrictCIDR(s.adminCIDRs, "admin"))
				admin.Use(s.rateLimit(s.limitAPI, "api"))

				admin.Group(func(manage chi.Router) {
					manage.Use(s.requireSession)
					manage.Use(s.requireRole(store.RoleManager))
					manage.Get("/users", s.handleListUsers)
					manage.Post("/users", s.handleCreateUser)
					manage.Patch("/users/{id}", s.handleUpdateUser)
					manage.Delete("/users/{id}", s.handleDeleteUser)
					manage.Post("/users/{id}/password", s.handleSetUserPassword)
					manage.Delete("/users/{id}/sso", s.handleUnlinkSSO)
					manage.Get("/invitations", s.handleListInvitations)
					manage.Delete("/invitations/{id}", s.handleRevokeInvitation)
				})

				// The auditor role reads the trail and nothing else. Both of
				// these are readable with a token: a SIEM pulling the trail
				// and a probe reading the status are exactly what tokens are
				// for.
				admin.Group(func(audit chi.Router) {
					audit.Use(s.requireRole(store.RoleManager, store.RoleAuditor))
					audit.Use(s.requireScope(store.ScopeAuditRead))
					audit.Get("/audit", s.handleAudit)
					audit.Get("/audit/export", s.handleAuditExport)
				})

				admin.Group(func(instance chi.Router) {
					instance.Use(s.requireRole(store.RoleAdmin))
					instance.Use(s.requireScope(store.ScopeInstanceRead))
					instance.Get("/instance", s.handleInstance)
					// Reading the webhook queue is a monitoring job, so a
					// token may do it. Declaring an endpoint is not an API
					// operation at all: it lives in peek.toml.
					instance.Get("/webhooks", s.handleWebhooks)
					instance.Get("/webhooks/deliveries", s.handleWebhookDeliveries)
				})

				// Poking the queue makes the server call out. That is an
				// administrator at a keyboard, not a script with a token.
				admin.Group(func(hooks chi.Router) {
					hooks.Use(s.requireSession)
					hooks.Use(s.requireRole(store.RoleAdmin))
					hooks.Post("/webhooks/{name}/test", s.handleWebhookTest)
					hooks.Post("/webhooks/retry", s.handleWebhookRetry)
				})

				// Customisation. A manager runs the users; the brand of the
				// whole instance is an administrator's decision, made in the
				// interface and not by a script.
				admin.Group(func(brand chi.Router) {
					brand.Use(s.requireSession)
					brand.Use(s.requireRole(store.RoleAdmin))
					brand.Get("/branding/admin", s.handleBrandingOptions)
					brand.Put("/branding/admin", s.handleSaveBranding)
					brand.Delete("/branding/admin", s.handleResetBranding)
					brand.Put("/branding/assets/{kind}", s.handleUploadAsset)
					brand.Delete("/branding/assets/{kind}", s.handleDeleteAsset)
					brand.Post("/branding/test-email", s.handleTestEmail)
				})
			})
		})
	})

	// Single sign-on, as plain browser navigation rather than through the
	// API: the single-page application never touches a code or a token.
	// Internal listener only, and behind the admin CIDR gate like every other
	// way in — the recipient pages need no identity at all.
	r.Group(func(sso chi.Router) {
		sso.Use(s.internalOnly)
		sso.Use(s.restrictCIDR(s.adminCIDRs, "admin"))
		sso.Use(s.rateLimit(s.limitLogin, "login"))
		sso.Use(noStore)
		sso.Get("/auth/sso", s.handleSSOStart)
		sso.Get(config.RedirectPath, s.handleSSOCallback)
	})

	// Branding stylesheet: served as a file so the CSP needs no inline styles.
	r.Get("/branding.css", s.handleBrandingCSS)
	// Logos and the favicon, on both listeners: a recipient page needs them.
	r.Get("/branding/{kind}", s.handleBrandingAsset)

	// Single-page application. The recipient pages are the only ones the
	// public listener needs, but the SPA is one bundle: it is served on both
	// listeners and the API gate above is what actually protects creation.
	r.NotFound(s.ui.ServeHTTP)
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		// On the public listener a 405 would say "this path exists, you used
		// the wrong verb" — which is exactly what the internal-only routes
		// must not admit. Out there, everything unmatched is simply absent.
		if listener == listenerPublic {
			writeError(w, r, http.StatusNotFound, "not_found", "Not found.")
			return
		}
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
	})
	return r
}

// Serve starts every configured listener and blocks until the context is
// cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	type binding struct {
		name string
		addr string
	}
	bindings := []binding{{listenerInternal, s.cfg.Server.InternalListen}}
	if s.cfg.Server.PublicListen != "" {
		bindings = append(bindings, binding{listenerPublic, s.cfg.Server.PublicListen})
	}

	tlsCfg, err := s.tlsConfig()
	if err != nil {
		return err
	}

	errs := make(chan error, len(bindings))
	var wg sync.WaitGroup

	for _, b := range bindings {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", b.addr)
		if err != nil {
			s.shutdown(context.Background())
			return fmt.Errorf("listen on %s (%s): %w", b.addr, b.name, err)
		}
		if s.cfg.Server.ProxyProtocol {
			if s.trusted.Empty() {
				_ = ln.Close()
				s.shutdown(context.Background())
				return errors.New("server.proxy_protocol requires server.trusted_proxies: an untrusted peer could otherwise forge its source address")
			}
			ln = newProxyListener(ln, s.trusted)
		}
		if tlsCfg != nil {
			ln = tls.NewListener(ln, tlsCfg)
		}

		srv := &http.Server{
			Handler:           s.Handler(b.name),
			ReadHeaderTimeout: 15 * time.Second,
			ReadTimeout:       s.cfg.Server.ReadTimeout.Std(),
			WriteTimeout:      s.cfg.Server.WriteTimeout.Std(),
			IdleTimeout:       s.cfg.Server.IdleTimeout.Std(),
			MaxHeaderBytes:    s.cfg.Server.MaxHeaderBytes,
			ErrorLog:          nil,
		}
		s.mu.Lock()
		s.servers = append(s.servers, srv)
		s.listeners = append(s.listeners, ln)
		s.mu.Unlock()

		s.log.Info("listening",
			"listener", b.name,
			"addr", ln.Addr().String(),
			"tls", tlsCfg != nil,
			"proxy_protocol", s.cfg.Server.ProxyProtocol,
			"routes", routeScope(b.name))

		wg.Add(1)
		go func(srv *http.Server, ln net.Listener, name string) {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("%s listener: %w", name, err)
			}
		}(srv, ln, b.name)
	}

	select {
	case <-ctx.Done():
	case err := <-errs:
		s.shutdown(context.Background())
		return err
	}

	grace, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownGrace.Std())
	defer cancel()
	s.shutdown(grace)
	wg.Wait()
	return nil
}

// Addrs returns the bound addresses, which tests need when they listen on :0.
func (s *Server) Addrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for i, ln := range s.listeners {
		name := listenerInternal
		if i > 0 {
			name = listenerPublic
		}
		out[name] = ln.Addr().String()
	}
	return out
}

func (s *Server) shutdown(ctx context.Context) {
	s.mu.Lock()
	servers := append([]*http.Server(nil), s.servers...)
	s.servers = nil
	s.listeners = nil
	s.mu.Unlock()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
	}
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	switch s.cfg.TLS.Mode {
	case "none", "":
		return nil, nil
	case "file":
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	case "acme":
		// ACME is milestone M4. Refusing loudly beats silently serving plain
		// HTTP on a listener the operator believes is encrypted.
		return nil, errors.New("tls.mode = acme is not wired yet (milestone M4); use mode \"file\" or terminate TLS on the proxy")
	default:
		return nil, fmt.Errorf("tls.mode %q is not supported", s.cfg.TLS.Mode)
	}
}

func parseCIDRs(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("%q is neither an IP nor a CIDR", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

func routeScope(listener string) string {
	if listener == listenerPublic {
		return "recipient routes only"
	}
	return "all routes"
}

// chiRouteContext returns the matched route pattern for the access log.
func chiRouteContext(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return ""
}
