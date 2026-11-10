# Architecture

How the code is laid out, which way dependencies point, and where M2 plugs in.
The dependency rules here are enforced by `internal/architecture`, so this file
and the code cannot drift apart without a test failing.

## Repository layout

```
cmd/
  mei/               the CLI entry point (stamps the version, calls internal/cli)
  meiosisd/          the MCP daemon entry point (stamps the version, calls internal/daemon)
internal/            implementation; not importable from outside the module
  daemon/            the meiosisd implementation: MCP over stdio and a Unix socket
  repoconfig/        per-repository settings (.meiosis/config.yaml) and the enforcement policy
  cli/               cobra commands, one file per command group; the only place that
                     prints to a terminal
                     (templates/ holds the files `mei init` writes)
  server/            HTTP server: Git smart-HTTP, /mcp, /api/v1, /metrics, auth
  mcp/               tools (one tools_<area>.go per area: schema + handler),
                     JSON-RPC, REST adapter, idempotency
  pushhook/          the git receive hooks (`mei hook ...`), run as separate processes
                     (hook.go: env and auth; prereceive.go: decide; postreceive.go: record)
  graph/             the domain core: intents, attempts, workspaces, evidence,
                     authority, ref updates; signs and stores everything
  identity/          capability tokens, delegation, revocation
  evidence/          report adapters (JUnit, SARIF, coverage, CycloneDX, go test)
  gitops/            reading Git: changed paths, added lines, trees -> worlds
  scope/             glob scope engine (allow/deny, narrowing)
  secrets/           credential scanner
  textdiff/          unified diff generation
  metrics/           Prometheus-format metrics
  jsonschema/        the JSON Schema subset used for evidence payloads
  acceptance/        end-to-end tests against the real binaries
  architecture/      the dependency-rule tests
pkg/                 importable building blocks with stable contracts
  spec/v1/           the object model and canonical encoding (the format)
  crypto/            Ed25519 keys and signatures over canonical JSON
  worlds/            world hashing (BLAKE3 over a tree)
  storage/           the storage interface; storage/sqlite is the one backend
  gitserver/         Git smart-HTTP via `git http-backend`
spec/
  v1/                the format specification (prose and JSON Schemas)
  conformance/       language-agnostic fixtures and known-answer vectors
docs/                operations, API, threat model, status, plans
scripts/             installers, release build, hook installer
tools/commitlint/    Conventional Commits checker (Go; replaces npm commitlint)
lefthook.yml         git hooks (replaces husky)
```

`pkg/` is for code another program could reasonably import and that we promise
not to break casually. Everything else is `internal/`. When in doubt, put it in
`internal/`: moving something into `pkg/` later is easy, the reverse is not.

## Dependency direction

```
cmd ──► cli ──► server ──► mcp ──► graph ──► identity ──► pkg/*
              │          │          │
              └──► pushhook ────────┤       scope, secrets, textdiff,
                                    └──►    metrics, jsonschema (leaves)
```

- **`pkg/spec/v1` imports nothing from the module.** It is the format.
- **Leaves** (`secrets`, `textdiff`, `metrics`, `jsonschema`, `scope`) know nothing
  of the object graph and can be tested and reused alone.
- **The domain core** (`identity`, `graph`, `evidence`, `gitops`) never imports a
  transport or the CLI, and does no networking.
- **Transports** (`mcp`, `server`, `pushhook`) sit above the core and may not
  import each other upward, nor `cli`.
- **`cmd/*` is thin**: stamp the version, call one `internal` package (`cli` or
  `daemon`), exit. The rule is enforced for both entry points. Logic lives where it can be tested.
- **Storage** is reached through `pkg/storage`. Only the composition roots
  (`internal/daemon`, `internal/cli`, `internal/server`, `internal/pushhook`) name the
  SQLite backend, so adding another is a change in those places.

The exact table is in `internal/architecture/architecture_test.go`. To add a
package, add it to the table, with the imports it must not make.

## How the pieces fit

- **Every durable object is signed** over its RFC 8785 canonical form and is
  stored immutably; what changes (an intent's status, an attempt's progress) lives
  in a separate signed state record. See `spec/v1`.
- **One code path for every surface.** The MCP tools, the JSON API and the CLI all
  call `internal/graph`; `internal/mcp` is the only place that turns a tool call
  into those calls, and it serves MCP and REST from the same handlers.
- **Git is a surface, not the store of truth.** `pkg/gitserver` serves repositories
  with `git http-backend`; `internal/pushhook` runs inside git's receive hooks to
  enforce scope and token authority, scan for secrets and record a signed world
  hash per ref update. A plain `git clone` of the repository is the escape hatch.
- **Worlds.** A world is a BLAKE3 hash over a tree's files (`pkg/worlds`). Evidence
  binds to a world; when the world changes, the evidence is no longer counted.
- **Workspaces** are overlays on a base world with a hash-linked operation log
  (`internal/graph/workspace.go`), which is what makes fork O(1) and undo exact.

## Conventions

- **Errors**: sentinel errors per package (`ErrInvalidParams`, `ErrTokenAltered`),
  wrapped with `%w`; callers use `errors.Is`. `internal/mcp.Classify` maps them to
  HTTP statuses and API codes, so a new sentinel needs a line there.
- **Context**: methods that touch storage take a `context.Context` first.
- **Time**: servers stamp times; a client-supplied timestamp is ignored.
- **No panics** across package boundaries; no global state apart from the version.
- **Tests**: table tests next to the code; `internal/acceptance` for anything that
  must work as a user runs it; property tests where an invariant is the contract
  (scope narrowing) and fuzzing where input is hostile (report adapters).
- **Docs travel with code**: a change to an object, tool or flag updates `spec/v1`,
  `docs/api.md` or the agent instructions in the same change.

## Where M2 plugs in

See [`plan-m2.md`](plan-m2.md) for the plan. Each M2 area has a place:

| M2 work | Goes in | Notes |
|---|---|---|
| Comparable worlds (per-file manifests for pushed trees) | `pkg/worlds`, `internal/gitops`, `internal/graph` | Today a pushed tree has only a hash; M2 stores its manifest. |
| Footprints, invalidation | `internal/graph` (new `footprint.go`) | `Evidence.Footprint` and `ExpiresAt` already exist in the spec. |
| Policy engine | new `internal/policy`, behind an interface | Keep the engine swappable (decision D1); must not import transports. Add it to the architecture table. |
| Verdicts and merge, protected refs | `internal/graph`, `internal/pushhook` | `pkg/spec/v1/verdict.go` already defines the object. |
| Web UI | new `internal/web`, mounted by `internal/server` | Server-rendered, embedded templates, no JS build step (decision D3). |
| Principal registry, verify-on-read | `internal/identity`, `internal/graph` | Closes the stored-objects-are-not-re-verified gap. |
| Export/import | `internal/cli`, `internal/graph` | Must verify signatures on the way in. |
| Another storage backend | `pkg/storage/<name>` | Port the `sqlite` package's tests; run them against both. |

## What would be a smell

- A leaf package importing `graph`: it has stopped being a leaf.
- `net/http` in `graph`, `identity`, `scope` or `pkg/spec`.
- A handler that does work instead of calling the graph (the CLI and MCP would diverge).
- A second implementation of scope, hashing or canonicalisation. There is one each.
- A new object type with no `spec/v1` document and no conformance fixture.
