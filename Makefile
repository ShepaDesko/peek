# Peek — development and release tasks.
#
# Everything runs natively: there is no Docker anywhere in this file, and the
# only build output is a single static binary.

SHELL := /bin/sh
GO ?= go
NPM ?= npm

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
SIGNING_KEY ?=

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE) \
	-X github.com/ShepaDesko/peek/internal/update.SigningPublicKey=$(SIGNING_KEY)

# ./... would also match web/node_modules, which ships a stray Go package.
PKGS := ./cmd/... ./internal/... ./tools/...

BIN_DIR := bin
WEB_DIST := web/dist
EMBED_DIST := internal/webui/dist

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- dependencies -----------------------------------------------------------

.PHONY: deps
deps: ## Install Go and frontend dependencies
	$(GO) mod download
	cd web && $(NPM) ci || $(NPM) install

# --- build ------------------------------------------------------------------

.PHONY: web-build
web-build: ## Build the SPA and stage it for embedding
	cd web && $(NPM) run build
	# Empty the directory without removing it: .gitignore is the one file in
	# there that is committed, and `rm -rf` on the directory takes it with
	# everything else. Leaving stale bundles behind is the other failure —
	# the file names are content-hashed, so a second copy does not overwrite
	# the first, it joins it, and the size budget then measures both.
	find $(EMBED_DIST) -mindepth 1 -not -name .gitignore -delete
	cp -r $(WEB_DIST)/. $(EMBED_DIST)/

.PHONY: build
build: web-build ## Build the peek binary with the interface embedded
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/peek ./cmd/peek

.PHONY: build-go
build-go: ## Build the binary without rebuilding the interface
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/peek ./cmd/peek

.PHONY: install-local
install-local: build ## Install the binary into /usr/bin (needs root)
	install -m 0755 $(BIN_DIR)/peek /usr/bin/peek

# --- development ------------------------------------------------------------

.PHONY: dev
dev: ## Run the API and the Vite dev server together
	@echo "API on http://127.0.0.1:8080, interface on http://127.0.0.1:5173"
	@trap 'kill 0' INT TERM; \
	PEEK_CONFIG=$(CURDIR)/peek.dev.toml $(GO) run ./cmd/peek serve & \
	cd web && $(NPM) run dev & \
	wait

.PHONY: dev-config
dev-config: ## Write a development configuration in the working directory
	PEEK_CONFIG=$(CURDIR)/peek.dev.toml $(GO) run ./cmd/peek setup \
		--non-interactive --force \
		--config $(CURDIR)/peek.dev.toml \
		--public-url http://127.0.0.1:8080 \
		--mode internal \
		--internal-listen 127.0.0.1:8080 \
		--db sqlite --dsn $(CURDIR)/.dev/peek.db \
		--data-dir $(CURDIR)/.dev \
		--anonymous-create

# --- quality ----------------------------------------------------------------

.PHONY: test
test: test-go test-web ## Run every test suite

.PHONY: test-go
test-go: ## Run the Go tests with the race detector
	$(GO) test -race $(PKGS)

.PHONY: test-web
test-web: ## Run the TypeScript tests (crypto vectors included)
	cd web && $(NPM) run test

.PHONY: vectors
vectors: ## Regenerate the shared crypto test vectors
	$(GO) run ./tools/genvectors

.PHONY: openapi
openapi: ## Regenerate api/openapi.json from the route table
	$(GO) run ./tools/genopenapi

.PHONY: lint
lint: ## Run gofmt, go vet, golangci-lint and ESLint
	@test -z "$$(gofmt -l cmd internal tools)" || (echo "gofmt needed:"; gofmt -l cmd internal tools; exit 1)
	$(GO) vet $(PKGS)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipped"
	cd web && $(NPM) run lint

.PHONY: fmt
fmt: ## Format Go and TypeScript sources
	gofmt -w cmd internal tools
	cd web && $(NPM) run format

.PHONY: vuln
vuln: ## Check Go dependencies for known vulnerabilities
	@command -v govulncheck >/dev/null 2>&1 || $(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck $(PKGS)

.PHONY: budget
budget: ## Check the size budgets from section 13 of the brief
	$(GO) run ./tools/budget

.PHONY: bench
bench: ## Run the crypto benchmarks
	$(GO) test ./internal/crypto -run '^$$' -bench . -benchmem

.PHONY: e2e
e2e: build ## Run the Playwright end-to-end suite
	cd test/e2e && $(NPM) install && $(NPM) run test

# --- release ----------------------------------------------------------------

.PHONY: snapshot
snapshot: web-build ## Build release artefacts locally (no publishing)
	@command -v goreleaser >/dev/null 2>&1 || (echo "install goreleaser first: https://goreleaser.com"; exit 1)
	# sign needs the minisign key, sbom needs syft; CI installs both for a real
	# release. A local snapshot is for looking at the packages, so skip them
	# rather than fail on the last step with every artefact already built.
	goreleaser release --snapshot --clean --skip=sign,sbom

.PHONY: clean
clean: ## Remove build outputs
	rm -rf $(BIN_DIR) $(WEB_DIST) dist .dev
	rm -rf $(EMBED_DIST)
	mkdir -p $(EMBED_DIST)
	git checkout -- $(EMBED_DIST) 2>/dev/null || true
