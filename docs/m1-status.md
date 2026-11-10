# M1 status: what works, what does not

This is the sequencing rule's "here is what is missing" (SRS §10): a working
primitive, published with an honest account of its gaps, before M2 exists.

**The M1 exit criterion is met and is tested on every build.** *A solo developer
with one agent gets a rejected out-of-scope write and a provenance record, in
under 5 minutes from download, with no config.* `internal/acceptance` runs it
against the real binaries; on a laptop it takes about a second after the
binaries exist.

**M1 is complete except for the items under "Not done"** (ConnectRPC, SSH, signed
commits, verify-on-read, OTLP traces, benchmarks for the NFR-1/2 targets, and the
licence decisions). Everything else M1 targets is implemented and tested. The
tables say which is which; nothing is marked done that is not exercised by a test.

## Requirements targeted at M0 and M1

✓ done and tested · ◐ partly done, gap stated · ✗ not done

### Identity and capability (FR-1)

| | Requirement | Status |
|---|---|---|
| FR-1.1 | Typed principals with Ed25519 keys | ◐ Principals are typed by their ID prefix and sign with Ed25519 keys held in files. There is no principal registry; a key is bound to a principal only through tokens' `holder_key`. |
| FR-1.2 | Every mutation signed; unverifiable signatures rejected | ◐ Every object is signed over its RFC 8785 canonical form. Tokens and delegation chains are verified on every use. Stored objects are not re-verified when read back, so a record altered directly in the database would not be caught. |
| FR-1.3 | `strict` mode | ◐ Strict mode is on by default after `mei init`: the daemon and `mei serve` refuse to run without capability enforcement, and a push needs a valid token. Git commit signatures are **not** checked. |
| FR-1.4 | Tokens scoped by path, operations, spend ceiling, TTL | ✓ |
| FR-1.5 | Delegation only to a strict subset; widening refused at issuance | ✓ Also re-checked on every verification. |
| FR-1.6 | Chain from any write back to the originating human | ✓ for MCP writes and delegations (`mei chain`, `authority_chain`) and for pushes (the token chain is in each ref update). The record is written just after the write, not in the same transaction. |

### Repositories and workspaces (FR-2)

| | Requirement | Status |
|---|---|---|
| FR-2.1 | Git protocol v2 over HTTP and SSH | ◐ HTTP only, tested with git at protocol v0, v1 and v2. SSH is deferred to M2. libgit2 and JGit were not tested (RK-6 stays open). |
| FR-2.2 | Every ref update produces a signed, content-addressed world hash | ✓ Signed by the server that observed the push, not by the pusher (who presents a bearer token, not a key). |
| FR-2.3 | O(1) workspace fork | ✓ A fork is one operation pointing at the source's head (`workspace_fork`, `mei work fork`). Benchmarked: about 0.35 ms for 10 or 1,000 files. |
| FR-2.4 | Virtual workspaces without a full clone | ◐ An agent writes files into a server-side workspace over MCP, with no checkout. That workspace is an overlay on an empty world unless it starts from a previously committed world; it does not start from the contents of a git branch. |
| FR-2.5 | Per-workspace operation log, every operation undoable | ✓ Signed, hash-linked, with a snapshot every 32 operations (`workspace_oplog`, `mei op log`). Undo is refused, not guessed, when later work depends on the operation. |
| FR-2.6 | `mei op undo` restores the prior world hash | ✓ Undoing a commit restores the exact earlier world hash (tested). |

### Intent (FR-3)

| | Requirement | Status |
|---|---|---|
| FR-3.1 | Create, read, list, supersede via API, MCP and CLI | ◐ MCP, CLI and a JSON HTTP API (`/api/v1/tools/{name}`, [`docs/api.md`](api.md)) with idempotency keys on every mutation (IF-2). **ConnectRPC/gRPC is not provided**: it would need code generation and several modules beyond the dependency budget. |
| FR-3.2 | Intents immutable; successor via supersede | ✓ Status and supersession live in a separate signed state record. |
| FR-3.3 | Scope as allow/deny globs | ✓ |
| FR-3.4 | Scope enforced at write time | ✓ At `attempt_write`, re-checked at commit, and at `git push`. |
| FR-3.5 | Context pins record content digests | ✓ Recorded, and re-checked by `mei intent show`. Marking attempts stale when a pin changes is FR-3.6, M2. |
| FR-3.7 | DAG with `depends_on`/`parent`; cycles rejected | ✓ |
| FR-3.8 | Intent auto-derivation | ✓ `attempt_open` with a task derives the intent. |

### Evidence (FR-4)

| | Requirement | Status |
|---|---|---|
| FR-4.1 | Evidence bound to an explicit world hash | ✓ |
| FR-4.2 | Published schema per kind; custom kinds | ✓ |
| FR-4.3 | Adapters: JUnit, `go test -json`, SARIF, Cobertura/LCOV, CycloneDX | ◐ All of them, except CycloneDX **XML**, which is refused with a pointer to the JSON encoding. |
| FR-4.4 | Producer named; independence computed and stored | ✓ |
| FR-4.12 | Evidence immutable; corrections supersede | ✓ Only the original producer may supersede a record. |

### Other

| | Requirement | Status |
|---|---|---|
| FR-8.5 | A plain `git clone` is a complete escape hatch | ✓ Tested. |
| NFR-4.5 | No outbound connections by default | ✓ Shipped code contains no outbound networking, and the sockets of a full session are inspected and are loopback only. A network-namespace test would be stronger and is not done. |
| NFR-5.1 | Single static binary, no cgo | ✓ Built with `CGO_ENABLED=0` in CI. Cross-compiled release targets are the release script's job. |
| NFR-5.4 | Time to first value under 5 minutes | ✓ Measured from the built binary; download time is not included. |
| RK-8 | Under 40 direct modules | ✓ 7. |

## Found by the completeness audit, and what became of it

| | Requirement | Status |
|---|---|---|
| §5.3 | MCP `evidence.query`, `workspace.fork`, `workspace.diff` | ✓ Added as `evidence_query`, `workspace_fork`, `workspace_diff`, plus `workspace_oplog` and `workspace_undo`. `workspace_diff` emits a unified diff that `git apply` accepts (tested). |
| §5.4 | `mei work start / status / submit` | ✓ Also `mei work fork`, `mei op log`, `mei op undo`. `mei login` is M3 (OIDC). |
| §4.3, §11.4 | Conformance suite with canonical-encoding and signature vectors | ✓ `spec/conformance/vectors/`: RFC 8785 cases including the RFC's own worked example, deterministic Ed25519 signatures, content IDs, world hashes. `verify_vectors.py` checks them with no Go code and passes. Fixtures also cover operations, secret findings and forked attempts. |
| IF-2 | Idempotency keys | ✓ On every mutating tool, over MCP and the JSON API. Exactly-once within one server process; a daemon and `mei serve` sharing a database do not coordinate. |
| NFR-5.2 | First run is `mei serve` and nothing else | ✓ In an empty directory `mei serve` initialises (strict, keys, token) and serves. `--no-init` restores the old refusal. Tested against the real binary. |
| NFR-4.6 | Threat model | ✓ [`docs/threat-model.md`](threat-model.md), with the test behind each defence and the weaknesses stated. Review at each minor release. |
| NFR-4.4 | Secret scanning on push | ◐ Implemented, tested and recorded on the ref update; `secrets: block` refuses. It is a tripwire: unrecognised secrets pass, the default is `warn`, and history already pushed is not rescanned. "Policy may block on findings" waits for the M2 policy engine. |
| NFR-3.3 | Consistent-snapshot backup | ✓ `mei backup` / `mei restore`, checksum and integrity-checked, procedure in [`docs/operations.md`](operations.md). NFR-3.4 (replay-and-compare) needs the M3 audit log. |
| NFR-5.5 | Prometheus metrics, OTLP traces | ◐ Prometheus text at `/metrics` (loopback only). **No OTLP traces.** Pushes are not counted (they run in git hook processes). |
| NFR-6.x | Open-source hygiene | ◐ Apache-2.0 `LICENSE` present (the SRS header says MIT; the SRS contradicts itself). No DCO check, no spec CC-BY notice. These are decisions for the project's owners. |

## Not done

- ConnectRPC / gRPC (the JSON API stands in).
- SSH transport (M2); libgit2 and JGit were not tested (RK-6).
- Verification of git commit signatures in `strict` mode.
- Signature verification when stored objects are read (needs the principal registry, M2).
- OTLP traces.
- Benchmarks for NFR-1.x and NFR-2.x beyond the fork benchmark. Until they run in CI they are wishes.
- A network-namespace test of the air-gap claim.
- DCO and spec-licence decisions.

**None of the M1 work is committed.** It is 130 or so changed files in the working
tree of `feat/m1`, on top of the pre-M1 merge commit. It builds, passes
`MEI_REQUIRE_SOCKET_CHECK=1 go test -race ./...` and `golangci-lint` (0 issues),
and cross-compiles for linux/darwin amd64 and arm64 and windows/amd64, but nothing is saved in history or reviewed.

## Things that are not in the SRS's M1 list but that you will hit

- **Nothing merges.** There are no verdicts, no merge, and no policy gate. Evidence is recorded and its independence and freshness are shown, but nothing acts on them yet. That is M2.
- **Evidence goes stale only when its world changes.** Footprints and automatic invalidation by footprint are M2 (FR-4.6, 4.7). `mei attempt show` and `mei status` say "counted", "stale" or "superseded" on that basis alone.
- **No review surface.** There is no web UI (M2) and no `mei review`.
- **Worlds are a placeholder.** A world hash is BLAKE3 over a tree's files in path order. The format is stable within this release but is to be replaced by zygote/vfs, which will change every world hash. Hashing a pushed tree reads every file, so it is slow for very large repositories.
- **Pushing:** deleting a ref and rewriting history are refused outright, not configurable. A ref update is recorded after the ref has moved; if recording fails the pusher is told and the ref has still moved. Tags are accepted but not specially handled. There is no LFS.
- **MCP:** tool names use underscores (`attempt_open`), not the dots in the SRS, because some MCP clients reject dots. The `/mcp` endpoint acts as a single principal (the repository's agent), since each principal must sign what it creates with its own key. Mutating tools take an `idempotency_key`. Over stdio a single message is limited to 1 MiB.
- **Storage:** SQLite only. No Postgres or object store, no export/import (FR-8.4, M2), no garbage collection (FR-2.7, M2).
- **Audit:** the authority log is append-only and signed but is not a Merkle log (FR-8.3, M3).
- **Performance:** none of the NFR-1.x or NFR-2.x targets has a benchmark yet. By the SRS's own rule, until one is in CI they are wishes.
- **Spec:** `spec/v1` is a draft and may break before v1.0 (NFR-6.5). Its changelog is in `spec/v1/README.md`.

## How this was checked

`make test` runs everything, including `internal/acceptance`: the exit-criterion
walkthrough, the SRS §11.3 adversarial scenarios (those whose defence exists in
M1; the others are present and skipped with the milestone that owns them), the
air-gap and no-cgo checks and the dependency budget. Parsers for evidence
reports are fuzzed (`go test ./internal/evidence -fuzz FuzzParse`), and the
delegation-narrowing logic has randomised property tests.
