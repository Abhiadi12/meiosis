# meiosis

**Source control where a green check expires.**

Evidence is bound to the exact state of the code it was produced against. When
that code changes, the proof goes stale on its own — no re-run required to find
out it no longer applies.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](go.mod)
[![Status](https://img.shields.io/badge/status-design%20stage-orange.svg)](#status)

---

```
$ mei status --merged --since 30d

  a4f1  add rate limiter to auth          verified
  8c02  refactor token parsing            verified
  1de9  cache user lookups                STALE

        test-run passed against world 615807ff
        HEAD is now world 32bd0271, and the footprint moved:

          ~ internal/auth/token.go        3 commits ago  (int_9f2a)
          ~ internal/auth/session.go      3 commits ago  (int_9f2a)

        this change has never been verified against the code it now runs on
```

Every CI system in use today produces green checks that quietly stop meaning
anything the moment someone else merges. Nobody notices, because the check is
attached to a branch name rather than to a tree.

meiosis attaches it to a content hash.

---

## Install

### Prebuilt binaries

Quick install (detects your OS/arch automatically — installs `mei` and
`meiosisd` into `/usr/local/bin` on Linux/macOS, `%LOCALAPPDATA%\mei` on
Windows):

**Linux/macOS:**

```sh
curl -fsSL https://github.com/subhranshus-mindfire/meiosis/releases/latest/download/install.sh | bash
```

**Windows (PowerShell, no bash needed):**

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://github.com/subhranshus-mindfire/meiosis/releases/latest/download/install.ps1 | iex"
```

Or download the archive for your platform from the
[latest release](https://github.com/mindfire-test/meiosis/releases/latest)
(each contains both `mei` and `meiosisd`):

| Platform | Archive |
| --- | --- |
| Linux x86_64 / arm64 | `mei-linux-amd64.tar.gz` / `mei-linux-arm64.tar.gz` |
| macOS Intel / Apple Silicon | `mei-darwin-amd64.tar.gz` / `mei-darwin-arm64.tar.gz` |
| Windows x86_64 / arm64 | `mei-windows-amd64.zip` / `mei-windows-arm64.zip` |

Linux/macOS example:

```sh
curl -sSLo mei-linux-amd64.tar.gz \
  https://github.com/mindfire-test/meiosis/releases/latest/download/mei-linux-amd64.tar.gz
tar xzf mei-linux-amd64.tar.gz
install -m 0755 mei meiosisd /usr/local/bin
mei version
```

Optionally verify the download against `SHA256SUMS.txt` from the same release.

The Windows installer also adds `mei.exe` to your user PATH — open a new
terminal after it finishes.

### From source

Requires Go 1.25+.

```sh
make build        # produces bin/mei and bin/meiosisd
export PATH="$PWD/bin:$PATH"
```

### First run

In any repository you want to govern, `mei init` bootstraps everything —
identity keys, a 30-day capability token, agent instructions, and MCP server
registration. It picks up VS Code (`.vscode/mcp.json`), Antigravity
(`~/.gemini/antigravity/mcp_config.json`), or both:

```sh
cd <your-project>
mei init                       # auto-detect IDE
mei init --ide vscode          # register with VS Code only
mei init --ide antigravity     # register with Antigravity only
mei init --ide vscode,antigravity   # both
```

Open the project in your IDE, approve the `meiosisd` server, and ask the
agent to declare an intent. `mei init` is idempotent; rerun it to repair a
partial setup, or `mei init --force` to regenerate secrets.

### Serve it over Git

```sh
mei serve                          # git + MCP on http://127.0.0.1:8484
mei remote add meiosis             # in your git repo: adds the remote and a credential helper
git push meiosis main              # recorded with the world hash of the pushed tree
git push -o intent=int_… meiosis main   # push under a declared intent: its scope is enforced
mei refs                           # every ref update, its world hash, who pushed it
```

Plain `git clone` and `git fetch` work against the same URL, so the code and its
history never depend on meiosis. Every request needs a capability token; the
credential helper mints a short-lived one from your repository key. Agents and CI
use `mei token bearer` (`git -c http.extraHeader="Authorization: Bearer $(mei token bearer)" push …`).
A push that names no intent is accepted under an implicit intent in `warn` mode.
Deleting refs and rewriting history are refused. Bind to a non-loopback address
only behind TLS: tokens are bearer credentials.

---

## Why this exists

The reviewable unit is wrong.

A diff is a record of edits, not a claim about behaviour. That was tolerable
when a human wrote every line and another human read them. It stops working
when most changes are produced by agents, because three things break at once:

- **Review attention.** Humans cannot read a thousand diffs a day, and reading
  faster is not the fix.
- **Semantic conflicts.** Two changes merge cleanly and are broken together.
  Git sees no conflict. Nobody does, until production.
- **The cost of proof.** Re-running full CI on every rebase of every branch
  stops being economically possible somewhere around agent number fifty.

None of those are Git's fault. Git tracks changes to files extremely well, and
it carries the Linux kernel without complaining. The gap is above Git: nothing
records what a change was *trying* to do, what evidence supports it, who or
what produced it, or whether that evidence still holds.

So the unit of change moves:

```
   from   commit → diff → PR
     to   intent → implementation → evidence → evaluation → merge
```

## The core idea

Three properties, and they only work together:

**Evidence expires.** Every verification result — test run, type check, security
scan, human review — is bound to the 32-byte hash of the tree it was produced
against, plus the set of paths it depends on. When any of them changes, the
record becomes stale automatically. Merged changes carry a live status:
`verified`, `stale`, or `unverified`.

**Evidence must be independent.** If the agent wrote the code and also wrote the
test that proves the code, that is self-graded homework. Every evidence record
names its producer, and policy can require that the producer is not the author.
This is enforced, not advisory.

**Agents are cryptographic principals.** Not a bot account with a shared token.
Each agent holds a keypair and a capability scoped by path, operation, spend and
TTL — and can only delegate a *strict subset* of its own scope to agents it
spawns. Every write traces back through the delegation chain to an originating
human.

## What it looks like in use

Scope is declared up front and enforced when the write happens, not discovered
in review:

```
$ mei work submit

  rejected — write outside declared scope

    intent int_9f2a  "add rate limiting to the auth middleware"
    allow            internal/auth/**, internal/middleware/**

    ~ internal/billing/invoice.go        not in scope
```

And every merge decision is derivable:

```
$ mei why 1de9

  decision   merge          .meiosis/policy/default.rego @ 7c1a9e
  risk       blast_radius=12  sensitive_paths=[]

  evidence
    ✓ test-run       pass   independent   fresh
    ✓ type-check     pass   independent   fresh
    ✓ replay-match   pass   independent   fresh    zygote bundle 3f9c
    · human-review          not required by policy at this risk level

  provenance
    agent:impl-3   claude-opus-5   delegated from human:lakin
    prompt 8a2f11…   1.2M tok in / 41k out   $2.14
```

## How it works

meiosis sits above Git storage and below your agent runtime. It replaces
neither.

```
   humans (CLI, web UI)        agents (MCP, gRPC)
            │                          │
            ▼                          ▼
   ┌───────────────────────────────────────────────┐
   │                 meiosis server                │
   │  intent · attempt · evidence · policy · merge │
   ├───────────────────────────────────────────────┤
   │  git wire protocol  │  content-addressed vfs  │
   └───────────────────────────────────────────────┘
            │                          │
      existing git tooling      evidence producers
      (clone / push / CI / IDE)  (CI, linters, replay)
```

`git clone`, `git push`, your editor, and your existing CI all work unchanged.
The Git remote is a complete escape hatch: a plain clone gives you every byte of
history with no dependency on meiosis. That is deliberate — anti-lock-in is a
feature, not an accident.

Agents reach the same functionality over **MCP**, served from the same binary.
No bindings to write.

## Status

**M1 works.** A developer with one agent gets scope enforced when the agent
writes, a signed provenance record for what it did, and test, lint, coverage and
SBOM reports recorded as evidence bound to the exact tree they describe. It
serves your repository over plain Git, enforces the same scope on pushes, and
records a signed world hash for every ref update. This is exercised end to end,
against the real binaries, on every build.

**It does not merge anything yet.** There is no policy gate, no verdict and no
review surface: evidence is recorded, and its independence and freshness are
shown, but nothing acts on them. Evidence goes stale when its world changes, not
yet when something it depends on does. Worlds use a placeholder hash. SSH,
Postgres, export/import and the web UI are not here. M1's own requirements are met except
ConnectRPC (a JSON API with idempotency keys stands in), SSH, signed-commit
verification, OTLP traces and CI benchmarks for the performance targets.
**[`docs/m1-status.md`](docs/m1-status.md) lists every requirement as done,
partly done or not done, and what you will trip over.** Operating notes are in
[`docs/operations.md`](docs/operations.md), the JSON API in
[`docs/api.md`](docs/api.md) and the security analysis in
[`docs/threat-model.md`](docs/threat-model.md).

| | | |
|---|---|---|
| **M0** | mostly done | object model, canonical encoding, signing, Git over HTTP, world hashes, SQLite. No SSH. |
| **M1** | complete, with stated gaps | intent, scope enforcement, workspaces with fork and undo, evidence ingest, capability tokens and delegation, MCP, JSON API, CLI, secret scanning, backup. |
| **M2** | next | footprints, automatic invalidation, verified/stale status, policy gate, review surface |
| **M3** | | speculative merge queue, incremental re-verification, semantic conflicts |
| **M4** | | continuous re-validation, outcome linking, calibration |

Code layout and dependency rules: [`docs/architecture.md`](docs/architecture.md). Everything in `docs/` is indexed in [`docs/README.md`](docs/README.md).

Requirement numbers (FR-…, NFR-…) refer to the SRS, which is not yet in this
repository; the [format specification](spec/v1/README.md) is.

## What this is not

Stated plainly, so nobody is surprised later:

- **Not a Git replacement.** Git is the storage and the escape hatch.
- **Not a CI system.** meiosis orchestrates and records evidence. It executes
  nothing.
- **Not an agent framework.** Any agent, any language, any model.
- **Not cloud-dependent.** No telemetry, no license check, no model API. Runs
  fully air-gapped, and there is a CI test that proves it.
- **Not a complete semantic conflict detector.** v1 detects exported-signature
  changes intersected with the reverse-dependency graph. That catches a useful
  fraction and misses plenty. Behavioural equivalence checking is a research
  problem and we will not pretend otherwise.

## Self-hosting

One static binary. No cgo, no Kubernetes, no external services.

```sh
mei init && mei serve
```

SQLite and the local filesystem by default. Postgres and any S3-compatible
store when you outgrow one node. Backup is a copy of the data directory.

## Contributing

Contributions are welcome, and design criticism is worth more than code right
now.

- **Apache-2.0**, chosen for the patent grant.
- **DCO sign-off** (`git commit -s`). No CLA — contributor volume is worth more
  to this project than the option to relicense.
- **Conventional Commits:** We strictly enforce conventional commits via local Git hooks. Run `./scripts/install-hooks.sh` immediately after cloning.
- The format specification in [`spec/v1`](spec/v1/README.md) is versioned independently of the
  server and has its own compatibility policy. The server is the reference
  implementation; the spec is the thing we hope outlives it.
- A language-agnostic conformance suite lives in `spec/conformance/` so other
  implementations are possible.

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Issues tagged `good first issue` are
real ones, not busywork.

Versioning is honest: `v0.x`, and **the object format will break before v1.0.**

## Why "meiosis"

Cells divide two ways, and the difference is the argument for this project.

**Mitosis** produces two genetically identical copies. It is duplication — fast,
faithful, unremarkable. That is `git branch`: a perfect copy of a tree, where the
only correctness question is whether the copy is exact.

**Meiosis** is the other one, and it is doing something considerably harder. One
cell produces four gametes, none identical to the parent or to each other. Along
the way it performs three operations mitosis has no equivalent for:

**Recombination.** Homologous chromosomes physically pair and exchange segments.
This is a genuine merge of two lineages, not one overlaid on the other. A
textual three-way merge is closer to overlay.

**Variation under selection.** Independent assortment alone yields 2²³
combinations in humans. Meiosis deliberately generates a population of candidates
and lets selection resolve them — which is how this system treats change: several
attempts at one declared intent, ranked by evidence, one merged, the rest kept
with their evidence intact.

**Checkpoints that arrest.** This is the part that names the project. Meiosis
will not proceed through an unverified state. The pachytene checkpoint halts the
cell until homologs have correctly synapsed and recombination intermediates are
resolved; the spindle checkpoint blocks separation until every chromosome is
properly attached. Failure means arrest, not a warning logged somewhere.
Verification is not a stage appended to division — it is a precondition the
machinery cannot bypass.

And the timing is the last argument. Prophase I — pairing, checking, recombining
— is by far the longest phase; in human oocytes it lasts decades, while the
division itself takes hours. Almost all of the cost is in establishing that the
exchange is sound. Almost none of it is in the exchange.

That is the correct ratio for software written by machines and governed by
humans. The change is cheap. The proof is the work.

Pronounced *my-OH-sis*. The CLI is `mei`.

## License

Apache-2.0 for the code. CC-BY-4.0 for the specification. See [LICENSE](LICENSE).
