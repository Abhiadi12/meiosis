# Contributing to meiosis

First off, thank you for considering contributing to meiosis! Contributions are welcome, and **design criticism is worth more than code right now.**

## Getting Started

1. **Ensure you have Go installed** (preferably the latest stable version, e.g., 1.25+).
2. **Fork the repository** on GitHub.
3. **Clone your fork locally**: `git clone https://github.com/YOUR_USERNAME/meiosis.git`
4. **Install Git hooks** (`make hooks`). They are managed by [lefthook](https://lefthook.dev), a single Go
   binary (installed with `go install` if missing), so no Node toolchain is needed:
   - `commit-msg`: Conventional Commits (scope is optional), checked by `tools/commitlint` (rules in `.commitlintrc.yaml`)
   - `pre-commit`: formats staged Go files (gofumpt and goimports) and checks `go.mod` is tidy
   - `pre-push`: `golangci-lint` (tests run in CI, or with `make test`)

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

## Releases

Releases are automatic; nobody tags by hand. The version comes from the commit
messages on `main` (Conventional Commits):

| commit type | effect (while the version is 0.x) |
|---|---|
| `feat` | minor bump: 0.1.0 to 0.2.0 |
| `fix`, `perf` | patch bump: 0.1.0 to 0.1.1 |
| breaking change (`feat!:` or a `BREAKING CHANGE:` footer) | minor bump before 1.0, major after |
| `docs`, `refactor`, `chore`, `ci`, `test`, `build`, `style` | no release by themselves |

How it runs (`.github/workflows/release-please.yml`):

1. Every push to `main` updates one open pull request titled
   `chore(main): release X.Y.Z`. It holds the next version number and the
   `CHANGELOG.md` entry.
2. **Merging that pull request is the release.** It creates the tag `vX.Y.Z` and
   the GitHub Release, then builds the binaries for Linux, macOS and Windows
   (amd64 and arm64) with checksums and installers, and attaches them.
3. Releases below 1.0 are marked as pre-releases.

Use a squash merge into `main`, so each change is one clean Conventional Commit.

One-time repository setting: *Settings, Actions, General, Workflow permissions*:
tick "Allow GitHub Actions to create and approve pull requests". The release pull
request is opened with the workflow's own token, so GitHub does not run CI on it;
CI has already run on `main`, which is what it is built from.

An emergency release is still possible: push a `vX.Y.Z` tag on a commit that is on
`main`, and `release.yml` builds and publishes it.

## Issues

If you find a bug or have a feature request, please check the existing issues first. Issues tagged `good first issue` are real ones, not busywork. If it hasn't been reported, open a new issue using the appropriate template.

## Legal & Sign-off

- **License:** Apache-2.0, chosen for the patent grant.
- **DCO Sign-off:** We require a Developer Certificate of Origin (DCO) sign-off for all commits (`git commit -s`). **No CLA** — contributor volume is worth more to this project than the option to relicense.
