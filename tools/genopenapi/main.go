// Command genopenapi writes api/openapi.json, the committed copy of the
// instance's own OpenAPI 3.1 description.
//
// The document a running instance serves at /api/v1/openapi.json is built from
// its route table and is the authority. This file exists so that someone
// reading the repository, or generating a client in CI, does not need a running
// server. CI regenerates it and fails on any diff, exactly as it does for the
// crypto vectors.
//
// Run it with: go run ./tools/genopenapi
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/ShepaDesko/peek/internal/config"
	"github.com/ShepaDesko/peek/internal/server"
	"github.com/ShepaDesko/peek/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genopenapi:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// A fixed configuration, so the committed document does not change with
	// whoever generated it. The real server substitutes its own public URL.
	cfg := config.Default()
	cfg.PublicURL = "https://secrets.example.com"
	cfg.Server.PublicListen = "0.0.0.0:8443"

	st, err := store.OpenMemory(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	srv, err := server.New(server.Options{
		Config:  &cfg,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Store:   st,
		Version: "v1",
	})
	if err != nil {
		return err
	}

	doc, err := srv.OpenAPI()
	if err != nil {
		return err
	}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')

	path := filepath.Join("api", "openapi.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // a repository directory
		return err
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil { //nolint:gosec // a repository file, committed as is
		return err
	}

	paths, _ := doc["paths"].(map[string]any)
	fmt.Printf("wrote %s (%d paths, %d bytes)\n", path, len(paths), len(buf))
	return nil
}
