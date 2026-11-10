.DEFAULT_GOAL := help
.PHONY: hooks commitlint help all build test test-short acceptance cover fuzz bench lint fmt fmt-check vet tidy tidy-check vectors cross check vuln clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
# Shipped binaries are built without cgo (pure Go, static). The race detector,
# unlike the product, needs cgo on Linux, so tests turn it on for themselves.
NOCGO := CGO_ENABLED=0
# Tools installed with `go install` live in $(go env GOPATH)/bin, which is often
# not on PATH: prefer one that is, else look there.
GOLANGCI_LINT := $(or $(shell command -v golangci-lint),$(shell go env GOPATH)/bin/golangci-lint)

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

all: check build ## Everything CI runs, then build

build: ## Build bin/mei and bin/meiosisd
	@mkdir -p bin
	$(NOCGO) go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mei ./cmd/mei
	$(NOCGO) go build -trimpath -ldflags "$(LDFLAGS)" -o bin/meiosisd ./cmd/meiosisd

test: ## Unit and acceptance tests with the race detector
	CGO_ENABLED=1 go test -race -count=1 ./...

test-short: ## Skip the slow end-to-end suites
	go test -short ./...

acceptance: ## The exit-criterion walkthrough and adversarial tests against real binaries
	MEI_REQUIRE_SOCKET_CHECK=1 CGO_ENABLED=1 go test -race -count=1 -v ./internal/acceptance/...

cover: ## Coverage report in coverage.html
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html

fuzz: ## Fuzz the report adapters for 30s
	go test ./internal/evidence -run '^$$' -fuzz FuzzParse -fuzztime 30s

bench: ## Benchmarks (workspace fork, and so on)
	go test ./internal/graph -run '^$$' -bench . -benchmem

lint: ## golangci-lint
	$(GOLANGCI_LINT) run

fmt: ## Format the code (gofumpt + goimports, as the linter checks)
	$(GOLANGCI_LINT) fmt

fmt-check: ## Fail if any file is unformatted
	$(GOLANGCI_LINT) fmt --diff

vet: ## go vet
	go vet ./...

tidy: ## go mod tidy
	go mod tidy

tidy-check: ## Fail if go.mod or go.sum need tidying
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak && go mod tidy; \
	  diff -q go.mod go.mod.bak >/dev/null && diff -q go.sum go.sum.bak >/dev/null; r=$$?; \
	  mv go.mod.bak go.mod; mv go.sum.bak go.sum; \
	  test $$r -eq 0 || { echo "go.mod/go.sum are not tidy: run 'make tidy'"; exit 1; }

vectors: ## Verify the conformance vectors with the independent Python implementation
	@python3 -c 'import blake3, cryptography' 2>/dev/null || { echo "needs: pip install blake3 cryptography"; exit 1; }
	python3 spec/conformance/verify_vectors.py

cross: ## Build every release target
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	  CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} go build -o /dev/null ./cmd/... && echo "ok $$t" || exit 1; done

vuln: ## Scan dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

hooks: ## Install git hooks (lefthook: format, vet, commit message, lint on push)
	./scripts/install-hooks.sh

commitlint: ## Check the commits on this branch against Conventional Commits
	go run ./tools/commitlint --from $$(git merge-base HEAD origin/main) --to HEAD

check: fmt-check lint tidy-check test ## What a pull request must pass

clean: ## Remove build output
	rm -rf bin dist coverage.out coverage.html
	go clean
