# Contributing to meiosis

First off, thank you for considering contributing to meiosis! Contributions are welcome, and **design criticism is worth more than code right now.**

## Getting Started

1. **Ensure you have Go installed** (preferably the latest stable version, e.g., 1.25+).
2. **Fork the repository** on GitHub.
3. **Clone your fork locally**: `git clone https://github.com/YOUR_USERNAME/meiosis.git`
4. **Install Git hooks** (`make hooks`). They are managed by [lefthook](https://lefthook.dev), a single Go
   binary (installed with `go install` if missing), so no Node toolchain is needed:
   - `commit-msg`: Conventional Commits, checked by `tools/commitlint` (rules in `.commitlintrc.yaml`)
   - `pre-commit`: formats staged Go files (gofumpt and goimports) and checks `go.mod` is tidy
   - `pre-push`: `golangci-lint` and the short test suite

   Skip them in an emergency with `LEFTHOOK=0 git commit ...`; CI runs the same checks.
5. **Check everything works** (needs `git`, Go, and `golangci-lint`; `lsof` makes the air-gap check run):
   ```bash
   make check      # formatting, lint (includes go vet), go.mod tidy, tests with -race
   make help       # every target: acceptance, cover, fuzz, bench, vectors, cross, vuln
   ```

## Where things go

Read [`docs/architecture.md`](docs/architecture.md) first. In short: `pkg/` is the
importable, stable part; `internal/` is everything else; dependencies point one
way, and `internal/architecture` fails the build if a package imports what it
must not. A change to an object, tool or flag updates `spec/v1`, `docs/api.md` or
the agent instructions (`internal/cli/templates/agents.md.tmpl`) in the same pull
request.

## Ground Rules & Core Philosophy

- **Cgo-Free Portability:** `meiosis` must remain a 100% pure Go codebase (`CGO_ENABLED=0`). Do not introduce C dependencies. We use `modernc.org/sqlite` instead of `mattn/go-sqlite3`.
- **The proof is the work:** Every logical change should be backed by tests. 
- **Code style:** We enforce rigorous style checks using `golangci-lint`. Always run `make check` before submitting a PR. Wrap errors with `%w` and test them with `errors.Is`.
- **Specification vs Implementation:** The format specification in `spec/v1` is versioned independently of the server and has its own compatibility policy. The server is the reference implementation; the spec is the thing we hope outlives it. A language-agnostic conformance suite lives in `spec/conformance/` so other implementations are possible.
- **Versioning:** Versioning is honest: `v0.x`, and **the object format will break before v1.0.**

## Branching & Pull Requests

1. **Create a branch** for your feature or bugfix:
   `git checkout -b feature/your-feature-name`
2. **Make your changes**. We recommend a step-by-step approach. Small, focused PRs are much easier to review than massive rewrites.
3. **Commit your changes**. Use descriptive commit messages strictly following the [Conventional Commits](https://www.conventionalcommits.org/) specification. The local hook you installed earlier will automatically check and enforce this before allowing the commit.
4. **Push your branch**: `git push origin feature/your-feature-name`
5. **Open a Pull Request** against the `main` branch. Ensure you fill out the provided PR template.

## Issues

If you find a bug or have a feature request, please check the existing issues first. Issues tagged `good first issue` are real ones, not busywork. If it hasn't been reported, open a new issue using the appropriate template.

## Legal & Sign-off

- **License:** Apache-2.0, chosen for the patent grant.
- **DCO Sign-off:** We require a Developer Certificate of Origin (DCO) sign-off for all commits (`git commit -s`). **No CLA** — contributor volume is worth more to this project than the option to relicense.
