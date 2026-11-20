package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/jobs"
	"github.com/ShepaDesko/peek/internal/server"
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

	srv, err := server.New(server.Options{
		Config:  &cfg,
		Logger:  log,
		Store:   st,
		Version: version,
	})
	if err != nil {
		return err
	}

	runner := jobs.New(&cfg, log, st, srv.Secrets())

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
