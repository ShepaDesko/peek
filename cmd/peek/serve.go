package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/ShepaDesko/peek/internal/audit"
	"github.com/ShepaDesko/peek/internal/config"
	pcrypto "github.com/ShepaDesko/peek/internal/crypto"
	"github.com/ShepaDesko/peek/internal/jobs"
	"github.com/ShepaDesko/peek/internal/mail"
	"github.com/ShepaDesko/peek/internal/server"
	"github.com/ShepaDesko/peek/internal/storage"
	"github.com/ShepaDesko/peek/internal/store"
)

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to peek.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath, false)
	if err != nil {
		return err
	}

	log, closer, err := newLogger(cfg.Log)
	if err != nil {
		return err
	}
	defer closer()

	log.Info("starting peek",
		"version", version,
		"commit", commit,
		"config", *configPath,
		"public_url", cfg.PublicURL,
		"driver", cfg.Database.Driver)

	if cfg.Server.TrustedProxies == nil && cfg.PublicURL != "" {
		log.Debug("no trusted proxy declared: X-Forwarded-* headers will be ignored")
	}

	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// The master key encrypts server-side metadata (TOTP seeds, credentials).
	// A missing one is not fatal: everything that does not need it keeps
	// working, and the features that do say so clearly.
	cipher, err := pcrypto.LoadServerCipher(cfg.MasterKeyFile)
	if err != nil {
		log.Warn("no usable master key: second factors and stored credentials are unavailable",
			"file", cfg.MasterKeyFile, "error", err.Error())
		cipher = nil
	}

	var mailer mail.Sender = mail.Discard{Log: log}
	if cfg.Mail.Host != "" {
		mailer = mail.New(cfg.Mail, log)
		log.Info("e-mail enabled", "host", cfg.Mail.Host, "from", cfg.Mail.FromAddress)
	}

	siem := audit.New(cfg.Audit.Syslog, log)
	defer func() { _ = siem.Close() }()

	// File storage. A backend that cannot be opened is fatal rather than
	// silently absent: an instance that accepts file secrets and drops them
	// would be worse than one that refuses to start.
	blobs, err := storage.Open(cfg.Storage)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	log.Info("file storage ready", "backend", blobs.Describe())

	srv, err := server.New(server.Options{
		Config:  &cfg,
		Logger:  log,
		Store:   st,
		Version: version,
		Cipher:  cipher,
		Mailer:  mailer,
		SIEM:    siem,
		Blobs:   blobs,
	})
	if err != nil {
		return err
	}

	runner := jobs.New(&cfg, log, st, srv.Secrets(), srv.Requests())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runner.Run(ctx)
	}()

	serveErr := srv.Serve(ctx)
	wg.Wait()
	if serveErr != nil {
		return serveErr
	}
	log.Info("stopped cleanly")
	return nil
}

// newLogger builds the structured logger. Output goes to stdout by default,
// which is what journald captures; log.file switches to a file for operators
// who prefer logrotate.
func newLogger(cfg config.Log) (*slog.Logger, func(), error) {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	out := os.Stdout
	closer := func() {}
	if cfg.File != "" {
		// 0600: a log file carries IP addresses and user agents.
		f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", cfg.File, err)
		}
		out = f
		closer = func() { _ = f.Close() }
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewJSONHandler(out, opts)
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(out, opts)
	}
	log := slog.New(handler)
	slog.SetDefault(log)
	return log, closer, nil
}
