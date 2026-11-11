# M2 plan: evidence that expires

**Status of this document.** Draft for review on `feat/m2`. Derived from the SRS
(§6, §8, §10, §11) and from what M1 actually left in the code. Section 3 breaks
down the core of M2, footprints and automatic invalidation, into components.

**Exit criterion (SRS §10).** *A merged change flips from `verified` to `stale`
on its own when an unrelated commit changes its footprint, and the UI shows why.*

Everything below is arranged to reach that as a single acceptance test, in the
style of `internal/acceptance`, and to keep it passing.

## 1. Where M1 leaves us, and what M2 has to build on

The footprint idea has a head start: `Evidence.Footprint` and `ExpiresAt` already
exist in the spec and are stored, and the adapters, supersede rules, scope and
delegation machinery are in. But M2's exit criterion needs four things M1 does
not have, and the plan is mostly about them:

1. **"Merged" does not exist.** M1 has no verdict, merge, or policy. An attempt
   is `open`; nothing moves it on.
2. **Worlds cannot be compared.** A world is one hash. To say "this footprint
   path changed between world A and world B" I need each world's file list with
   per-file digests (a manifest). Attempt worlds have one in the database. Worlds
   produced by `git push` have only a hash, so evidence about a pushed tree cannot
   be checked against a later push.
3. **No principal registry.** Objects are signed but a signature can only be
   checked where a key travels with the object (tokens). Export/import (FR-8.4)
   must verify signatures on the way in, so principals need keys on record.
4. **No dependencies for the policy engine, UI or zygote.** Each is a decision
   (section 2), and one is blocked on something outside this repository.

### M1 gaps M2 inherits (from `docs/m1-status.md`)

Not required by M2's exit, but they bite it: FR-1.2 stored objects are not
re-verified on read; FR-2.3 to FR-2.6 workspace fork, operation log and undo;
FR-2.4 attempts cannot start from a git branch; SSH; signed-commit checks;
**no benchmarks**, while §11.2 says every NFR in §7.1/§7.2 needs one that fails
the build. The optional carry-overs at the end of section 4 say which of these
M2 takes on.

## 2. Decisions to make before building (with a recommendation each)

### D1. Policy engine: OPA/Rego, Starlark, or neither (OD-3)

I measured it rather than guessed. A 12-line program that only evaluates one
Rego rule, built with `CGO_ENABLED=0`, comes to **28 MiB**, adds **26 entries to
`go.mod`**, and brings the module graph to **114 modules**; `mei` today is 17 MiB.

| | OPA / Rego | Starlark (`go.starlark.net`) |
|---|---|---|
| SRS says | chosen (OD-3), "revisit if dependency weight breaks NFR-5.3" | the stated fallback |
| NFR-5.3 container < 100 MB | fits: about 45 MB for both binaries | fits easily |
| RK-8 < 40 direct modules | fits: +1 direct (8) | +1 direct |
| The spirit of RK-8 | strained: a large transitive tree | no strain |
| Auditability, existing ecosystem | the reason it was chosen | users write a new language |

**Recommendation: OPA, behind a narrow `internal/policy` interface**, with the
binary size and module count recorded in CI so growth is visible, and with
network, time and randomness builtins stripped (`http.send`, `time.now_ns`,
`rand.*`, `opa.runtime`, environment access). That last part is required, not
optional: PR-1 says evaluation is pure, and NFR-4.5 says no outbound connections;
an unrestricted OPA breaks both. If the tree weight becomes a problem for
adopters, the interface lets Starlark replace it without touching callers.

### D2. What "merge" means in M2

M1 has no merge, and the SRS's merge queue is M3. M2 still needs a "merged"
state to flip. Options:

- **A. Verdict plus protected refs (recommended).** A verdict records the
  decision. A repository can *protect* refs (config, off by default): a push to a
  protected ref is accepted only if a `merge` verdict exists for a tree whose
  world hash equals the pushed tree's. An attempt becomes `merged` when such a
  push lands. Git stays the authority on history; meiosis decides *what may
  enter it*.
- B. The server writes the commit itself. This needs three-way merge or rebase
  when the base moved, which is exactly M3's auto-rebase. Doing it now means
  building M3's hardest part early.

A needs no merge algorithm and is enforceable with the pre-receive hook that
already exists. Its cost is that an agent must still deliver the tree through
git. B is the natural M3 follow-on.

### D3. Review surface (OD-4)

**Recommendation: server-rendered HTML** (`html/template`, `go:embed`, a little
vanilla JS), no JavaScript build step and no framework. The SRS wants it small
and its framework choice reversible; this adds no dependency and no `npm`.
Every page is a view over a JSON read API under `/api/v1/`, because "no feature
may exist in the UI that is not in the API" (§5.5). The SRS's ConnectRPC stays
out of scope until a client needs it.

### D4. `replay-match` and zygote (FR-4.9)

**This one is blocked, and I cannot plan it around the unknown.** FR-4.9 means
"accept a zygote run bundle, replay it server-side". zygote is a separate
repository (SRS §2.3) that is not here; I do not know the API of `vfs.Store` or
`trace.Bundle`, or whether replay runs the agent's code (which would conflict
with "meiosis executes nothing"). Proposal: build everything around it now (the
`replay-match` schema, binding the bundle digest to the attestation's
`run_bundle`, an interface for the replayer) and gate the real replay on
getting zygote's API. **What I need from you: the zygote repo or its API.**

### D5. Where file lists for pushed trees live

Storing a path-to-digest manifest per pushed world is simple and, for a
100,000-file repository, a few MB per push. A Merkle tree that shares unchanged
subtrees is better and is what `zygote/vfs` is meant to give. **Recommendation:
manifests now, behind a `WorldIndex` interface, so zygote/vfs replaces the
implementation, not the callers.** Digests are BLAKE3 of file content, the same
ones the world hash already uses.

## 3. Core components: footprints and automatic invalidation

This is the part of M2 that makes evidence expire (FR-4.6, 4.7, 4.10, 4.11). It
spans Phases 1, 2 and 5 below; this section names the components, what each owns,
and what already exists, so the phases can be split into issues.

### 3.1 The idea in one example

```
evidence E: kind=test-run, outcome=pass, world=W1, footprint=["internal/auth/**"]
main moves W1 → W2 → W3
changes(W1, W3) = { internal/auth/token.go (modified), README.md (modified) }
footprint ∩ changes = { internal/auth/token.go }   ⇒ E is stale, reason: token.go, first changed in W2's ref update
```

If only `README.md` had changed, E would be *carried*: its world is old, but
nothing it depends on differs, so it still counts. Nothing is re-executed in
either case.

### 3.2 Data flow

```
 git push ──► pushhook ──► RefUpdate{World, BaseWorld} ──► C1 WorldIndex (manifest per world)
                                                                 │
 evidence submit ──► C2 Footprint parser ──► Evidence.Footprint  │
   (CLI / MCP / adapters C3)        (normalised, signed)         ▼
                                                     C4 ChangeSet = Diff(manifest(E.World), manifest(current))
                                                                 │
                                         C5 Standing engine (pure): fresh | carried | stale | expired | superseded
                                                                 │      + reasons [{path, change, ref_update}]
                                    C6 Footprint index (fan-out) ┤
                                                                 ▼
                                C7 Surfaces: mei attempt show · mei status · evidence_query · policy input (Phase 3)
```

### 3.3 Components

| # | Component | Owns | Exists today | To build |
|---|---|---|---|---|
| C1 | **WorldIndex** | For any world hash, its manifest (path → BLAKE3 digest) | Attempt worlds store a manifest under `KindWorld` (`internal/graph/attempt.go`). Ref updates store only `World`/`BaseWorld` hashes (`pkg/spec/v1/ref_update.go`). | One interface for both kinds; manifests for pushed trees (Phase 1.1, 1.2) |
| C2 | **Footprint parser** | Turning `[]string` into typed, validated, canonical entries | `Evidence.Footprint []string` is stored and scope-checked at submit (`internal/mcp/tools_evidence.go`); there is no syntax beyond "a string" | `ParseFootprint` (see 3.4) |
| C3 | **Footprint sources** | Where footprints come from, per adapter | Adapters in `internal/evidence` (JUnit, `go test -json`, SARIF, Cobertura/LCOV, CycloneDX); none sets a footprint | Coverage → measured files; SARIF → files with results; `go test -json` → package directories (approximate, see 3.6); `--footprint` / MCP `footprint` for the rest |
| C4 | **ChangeSet** | Added / modified / deleted paths between two worlds | `changedPaths(before, after)` in `internal/graph/attempt.go`; `worlds.Diff` over in-memory trees | `Diff(a, b manifest) ChangeSet` with change kind per path, reused by C5 and the review diff |
| C5 | **Standing engine** | Classifying one evidence record against the current world | Two copies of a world-equality check: `graph.QueryEvidence` (`internal/graph/diff.go`) and `evidenceStanding` (`internal/cli/evidence_submit.go`) | One pure function, `Standing(e, current, changes, now) → (State, []Reason)`; both copies call it |
| C6 | **Footprint index** | Path → evidence IDs, for fan-out when a ref moves (SRS §4.4, NFR-1.4) | None | Built only if C5-on-read misses NFR-1.4 (see 3.5) |
| C7 | **Surfaces** | Showing standing and *why* | `mei attempt show` prints STALE/SUPERSEDED; `evidence_query` filters `counted/stale/superseded` | Add `carried` and `expired`, print reasons; feed `fresh`/`carried` into the policy input (Phase 3.2) |

### 3.4 Footprint syntax and parsing (C2)

Evidence is signed, so the footprint is normalised **before** signing; two
submissions with the same meaning produce the same bytes.

| Entry | Example | Meaning | M2 |
|---|---|---|---|
| Exact path | `internal/auth/token.go` | that file | accepted |
| Glob | `internal/auth/**`, `cmd/*/main.go` | any matching file (doublestar, as `internal/scope`) | accepted |
| Symbol | `sym:internal/auth.Verify` | an exported symbol | reserved, **rejected** with a pointer to M3 |
| Empty list | `[]` | whole world: stale on any change (M1 behaviour) | accepted |

Rules for `ParseFootprint`:

1. Same path validation as scope: relative, slash-separated, no `..`, no leading
   `/`, no empty segments. Reuse `internal/scope`'s validator; do not write a
   fourth one.
2. Globs must compile (`doublestar.ValidatePattern`).
3. Sort and de-duplicate. Drop entries covered by another (`a/**` covers `a/b.go`).
4. Cap the count (proposal: 1,000 entries) so one record cannot make every
   standing computation expensive.
5. A deleted or renamed footprint path counts as changed. Renames are a delete
   plus an add; M2 does not track them.

### 3.5 Standing rules (C5)

Evaluated in this order; the first match wins.

| State | Condition | Counts toward policy? |
|---|---|---|
| `superseded` | a later record by the same producer supersedes it (FR-4.12) | no |
| `expired` | `expires_at` is set and `now > expires_at` (FR-4.11), whatever the code did | no |
| `fresh` | `e.World == current` | yes |
| `stale` | footprint empty and `e.World != current`, **or** any footprint entry matches a path in `ChangeSet(e.World, current)` | no |
| `carried` | world differs, but no footprint entry matches any changed path | yes |

Properties the tests must hold:

- **Pure:** no clock, no I/O. `now` and the manifests are arguments.
- **Sound:** never `carried` when a footprint file's digest differs (Phase 2.2 property test).
- **Explained:** every `stale` has at least one reason `{path, change}`. Phase 5 adds which ref update first changed it, by walking ref updates oldest first.
- **Cost:** O(|changes| × |footprint|) glob matches per record. Compute on read
  first; build C6 only if the NFR-1.4 benchmark (under 200 ms per attempt) fails.
  C6 keys exact paths directly and globs by their literal prefix (`internal/auth/`
  for `internal/auth/**`).

### 3.6 Footprint quality

A footprint that is too small makes `carried` a lie, which is worse than no M2.
Rules:

- Adapters only emit a footprint when the report itself names the files
  (coverage, SARIF). Otherwise the footprint stays empty (whole-world) unless the
  submitter supplies one.
- A `go test -json` package footprint (`internal/auth/*`) misses transitive
  dependencies. It is opt-in (`--footprint-from-packages`) and recorded as
  approximate in the payload, not the default.
- Should a footprint be allowed outside the attempt's scope? Tests legitimately
  depend on code the attempt did not change. Today they are refused (open question 7, section 7).

### 3.7 Order and size

Estimates are for one contributor who is new to Go and to this codebase. Each
step includes understanding the code it touches and writing its spec, building
it, and testing it, including review rounds.

| Step | Component | Depends on | Understand + spec | Build | Test + review | Days |
|---|---|---|---|---|---|---|
| 1 | C2 `ParseFootprint` + wire into submit paths | nothing | 1 | 0.5 | 0.5 | 2 |
| 2 | C5 `Standing`, pure, with table tests; replace both existing copies | C2 | 1 | 0.5 | 0.5 | 2 |
| 3 | C4 `Diff` over manifests | C1 for pushed worlds; attempt worlds work today | 0.5 | 0.5 | 0.5 | 1.5 |
| 4 | C1 manifests for ref updates | Phase 1.2 | 1.5 | 1 | 1 | 3.5 |
| 5 | Soundness property test (Phase 2.2) | C2, C4, C5 | 0.5 | 0.5 | 0.5 | 1.5 |
| 6 | C3 coverage/SARIF footprints, `--footprint`, `--ttl` | C2 | 1 | 0.5 | 0.5 | 2 |
| 7 | C7 surfaces with reasons | C5 | 0.5 | 0.25 | 0.25 | 1 |
| 8 | C6 index, only if the benchmark needs it | C5, benchmark | 0.5 | 0.5 | 0.5 | 1.5 |
| | **Total** | | | | | **15 (13.5 without step 8)** |

Calendar time also depends on review turnaround and on the answer to question 7
(section 7), which step 1 needs.

Steps 1 and 2 need nothing from Phase 1 and can start immediately; they work for
attempt worlds today, which already have manifests.

## 4. Phases

Sizes are working days for one engineer, as for M1. The SRS allows about 25.

### Phase 0. Settle D1 to D5, and measure (2 days)

- Record the decisions in `docs/adr/`.
- CI gets a size and module-count guard so D1's cost is visible from the first commit.
- Start the benchmark harness (see Phase 9), because Phases 1 to 3 add code with targets.

### Phase 1. Worlds that can be compared (6 days). Foundation for everything after.

| # | Task | Done when |
|---|---|---|
| 1.1 | `WorldIndex`: for a world hash, its manifest (path to digest); implemented for attempt worlds (existing) and git trees (new) | One call answers for both kinds |
| 1.2 | Store a manifest for every ref update, content-addressed and shared between identical worlds; record the changed-path list (capped, with a count) on `RefUpdate` | A push records what it changed; `mei refs` can show it |
| 1.3 | `worlds.Diff(a, b)` over manifests: added, modified, deleted paths with digests | Property test: diff of a world with itself is empty; applying a diff reproduces the other manifest |
| 1.4 | Attempts can start from a ref: `attempt_open {base_ref}` seeds the workspace from that tree, blobs read from git rather than copied into the database (FR-2.4) | An attempt's `base_world` equals the ref's recorded world; committing an untouched workspace returns that same hash |
| 1.5 | Benchmark: diff of two 100,000-file manifests | Target set and recorded; guards later work |

### Phase 2. Footprints and invalidation (FR-4.6, 4.7, 4.11) (5 days)

- **Footprint syntax:** paths and globs now. Symbols (`sym:pkg.Name`) are
  reserved and rejected until M3's analysis exists, so no evidence is accepted
  with a footprint M2 cannot honour.
- **Standing of one piece of evidence**, computed, never stored:
  *fresh* (its world is the current one), *carried* (world differs but no
  footprint path has a different digest between the two worlds), *stale*,
  *expired* (`expires_at` passed), *superseded*. Evidence with no footprint is
  bound to its world exactly as in M1: stale on any change.
- **Adapters supply footprints where the report knows them:** Cobertura and LCOV
  list the files they measured, so coverage evidence gets a footprint for free.
  JUnit and `go test -json` do not name source files; their footprint is
  supplied with `--footprint` or stays whole-world.
- **Index:** `evidence_footprint(path)` (§4.4) for fan-out when a tree changes.
- **TTL (FR-4.11):** `--ttl` on submit; expiry applies regardless of footprint.

| # | Task | Done when |
|---|---|---|
| 2.1 | `evidence.Standing(e, currentWorld, index)` | Table tests for every state |
| 2.2 | **Soundness property test:** random trees and edits; evidence is never "carried" when a footprint path's content differs | Passes over millions of cases, as the delegation property test did |
| 2.3 | Footprint from Cobertura/LCOV; `--footprint`, `--ttl` flags; MCP parameters | Fixtures; `mei attempt show` names the carried and stale evidence |
| 2.4 | Reject unsupported footprint forms | Symbol footprints refused with a pointer to M3 |

### Phase 3. Policy (FR-5.3, 5.4, 5.8, 4.5; PR-1, PR-2) (7 days)

- **Where the policy comes from:** `.meiosis/policy/*.rego` read from the
  **target ref's tree**, not the working directory, so a policy change is itself
  a reviewed change (FR-5.3). The policy digest stored in a verdict is the
  digest of exactly the files evaluated.
- **Input document (§8):** `intent` (id, scope, `context_stale`), `attempt` (id,
  author, `scope_violations`), `evidence[]` (kind, outcome, `independent`,
  `fresh`, plus M2's `counted`, `carried`, `superseded`), `risk`, `principal`.
  It carries `"version": 1` because the SRS calls it stable. `risk.blast_radius`
  and `principal.calibration` belong to M3 and M4; they are present and marked
  not computed, so a policy cannot silently depend on them. `risk.sensitive_paths`
  comes from path patterns in policy config, with no code analysis.
- **Sandbox:** the builtin restrictions from D1; a wall-clock evaluation timeout;
  a memory limit on the input.
- **PR-2:** a policy that does not compile, or an evaluation that errors,
  produces a verdict of `escalate` with the error as its rationale. It never
  defaults open (verdict.md and §8 agree on this).
- **Shipped library:** helpers like `independent_pass(kind)` and a count of
  independent records, so FR-4.5 ("N independent records") is one line.
- **`mei init` writes a conservative default policy**, so M2 works with no
  Rego authoring: merge only with a fresh independent passing test run and no
  scope violations; otherwise escalate.

| # | Task | Done when |
|---|---|---|
| 3.1 | `internal/policy`: compile, evaluate, digest; builtin allow-list | Tests prove `http.send`, `time.now_ns`, `rand.intn` are unavailable |
| 3.2 | Input builder from the graph | Golden JSON files, checked against the spec fixture |
| 3.3 | `Verdict` creation: signed, with `policy_ref` and exact `policy_in` | Replaying `policy_in` against `policy_ref` reproduces the decision |
| 3.4 | PR-2 behaviour | A broken `.rego` yields `escalate` for every attempt (SRS §11.3 row, un-skipped) |
| 3.5 | Benchmark: policy evaluation p99 under 20 ms (NFR-1.3) | In CI |

### Phase 4. Merge decisions and protected refs (D2-A) (6 days)

- `merge_request` (MCP) and `mei merge request|status|why <attempt>`. `why`
  prints the full derivation: policy, inputs, each piece of evidence and its
  standing, risk (§5.4: "if a human cannot understand why something merged, the
  system has failed").
- **Human review verdicts:** `mei review approve|reject` records a verdict by a
  human. Rule to confirm with you: a human may approve an `escalate`, but may not
  override a policy `reject`; changing that takes a policy change, which is
  itself reviewed.
- **Protected refs:** `protect = ["refs/heads/main"]` in config. The pre-receive
  hook accepts a push to one only if a `merge` verdict exists for an attempt on
  the pushed world, made after the evidence it relied on. Post-receive marks the
  attempt `merged`, and the intent with it.
- **Stale base:** if the ref moved since the attempt's base, the verdict can
  still say merge, but the push is refused with "rebase required"; the rebase
  itself is M3.

| # | Task | Done when |
|---|---|---|
| 4.1 | `merge_request`, `mei merge ...`, `mei review ...` | Verdicts are signed, immutable, queryable |
| 4.2 | Protected-ref enforcement | A push of an unreviewed tree to `main` is refused with the missing requirement named |
| 4.3 | `merged` state transition | Attempt and intent status reflect delivery |
| 4.4 | Adversarial: an agent cannot satisfy the gate with its own evidence | SRS §11.3 "merge blocked" row, un-skipped |

### Phase 5. Verified / stale / unverified, live (FR-4.10, FR-3.6) (5 days)

- **Standing of a change** is computed from the policy's requirements and the
  standing of the evidence that meets them: `verified` (the requirements are met
  by evidence that is fresh or carried), `stale` (they were met, but the
  evidence no longer holds), `unverified` (never met).
- **Why, with attribution:** a stale change names the footprint path, the ref
  update whose manifest first differed, its commit and who pushed it.
  This uses Phase 1's manifests, and is what the UI will show.
- **FR-3.6:** pinned context is compared with the file's digest in the **current
  world's** manifest (deterministic, not the working directory); a change marks
  dependent attempts and merged intents `stale` in the report.
- Recomputed on read; benchmark NFR-1.4 (under 200 ms per attempt) in CI.

### Phase 6. Review surface and web UI (FR-5.1) (6 days)

- **Order of disclosure, per FR-5.1:** intent, evidence summary, change summary,
  textual diff, agent transcript. The change summary is file-level in M2
  (added/modified/deleted with sizes); the *semantic* summary is M3 and the page
  says so rather than imply it. The textual diff comes from `git diff` between
  the base and attempt worlds.
- **Transcript:** only if the repository opts in (NFR-4.2). Otherwise the page
  shows the prompt digest and says the text was not retained.
- Pages: review queue, attempt, change standing with reasons, ref history, audit
  list. JSON under `/api/v1/` first, HTML on top. Read-only; mutations stay in
  the API and CLI.
- Safe by construction: server-rendered with context-aware escaping, a strict
  Content-Security-Policy, no inline script, same-origin only, and the token
  required exactly as for git.

### Phase 7. `replay-match` (FR-4.9). Blocked on D4 (3 to 8 days)

Spike once zygote is available. Until then: schema, `run_bundle` binding, the
replayer interface and a refusing default, so everything else can ship.

### Phase 8. Principals, verification and export/import (FR-8.4, FR-1.1, FR-1.2) (6 days)

- **Principal registry:** `principals` records with public keys, written by
  `mei init`, by delegation (holder keys) and by `mei principal add`. Revoking a
  principal revokes everything delegated from it (FR-1.7, within 5 s: reads hit
  the store each call, so this is already the mechanism).
- **Verify on read and on import:** every stored object's signature is checked
  against its principal's key; a mismatch is reported by `mei doctor` and refused
  on import. Closes the M1 gap in FR-1.2.
- **Export/import:** all object kinds in canonical form (JSON lines per kind,
  plus the content blobs) in a documented layout under `spec/`. *Done when:*
  export, import into an empty store, export again gives byte-identical output.

### Phase 9. Benchmarks, hardening and acceptance (4 days)

- **Benchmarks in CI (§11.2):** NFR-1.2 evidence submit p99 under 50 ms, NFR-1.3
  policy, NFR-1.4 readiness, NFR-1.6 clone throughput against `git-daemon`. They
  fail the build on regression beyond a stated threshold.
- **The exit criterion as a test** (`internal/acceptance`): attempt, evidence
  with a footprint, merge verdict, push to a protected ref (merged, `verified`);
  an unrelated commit that touches an unrelated file leaves it `verified`
  (carried); a commit that changes a footprint file flips it to `stale`, and the
  page and `mei merge why` name the path, the commit and the pusher.
- Update `docs/m1-status.md` into a living status file; spec changelog; README.

### Optional carry-overs (take if there is slack, otherwise M3)

FR-2.7 garbage collection (a "should"); FR-2.3 to FR-2.6 workspace fork, operation
log and `mei op undo` (M1 "musts" that are still open); SSH transport;
signed-commit verification for strict mode; CycloneDX XML.

## 5. Order and parallelism

```
P0 ──► P1 ──► P2 ──► P5 ──► P6 ──► P9
        │      │             ▲
        │      └──► P3 ──► P4┘
        └──────────────────► P8
P7 (blocked on D4) joins at P9 if unblocked
```

- P1 is the critical path; start it first and alone.
- P2 and P3 are independent once P1's `WorldIndex` exists.
- P8 depends only on the registry, so it can run in parallel from the start of P2.
- P6's JSON API can start as soon as P4's verdicts exist.

## 6. Risks

| Risk | Mitigation |
|---|---|
| OPA's weight draws the objection RK-8 was written for | Narrow interface, size and module guard in CI, measured numbers in the ADR |
| OPA's defaults are impure and networked | Allow-list capabilities; tests prove the banned builtins fail |
| Manifests for very large repositories get big | `WorldIndex` interface; Merkle sharing via zygote/vfs later; benchmark early in P1 |
| Footprints that are wrong make "carried" evidence a lie | Soundness property test (2.2); evidence with no footprint stays whole-world; symbols refused |
| zygote's API is unknown (D4) | Spike first; everything else is built to not need it |
| The protected-ref gate surprises solo users | Off by default; the default policy is conservative but protection is opt-in |
| Server-signed and token-based records are weaker than self-signed ones | Documented in the spec; the registry in P8 lets the verifier state exactly what a signature proves |

## 7. Questions for you

1. **Policy engine:** OPA behind an interface (my recommendation), or Starlark?
2. **Merge:** verdict plus protected refs (A), or should the server create the commit (B)?
3. **UI:** server-rendered HTML, or do you want a JavaScript framework?
4. **zygote:** can you share the repository or its API? Without it Phase 7 stays a stub.
5. **Human override:** may a human approve over a policy `reject`? I propose not.
6. **M1 leftovers:** do FR-2.3 to FR-2.6 (workspace fork, operation log, undo) go into M2, or wait?
7. **Footprint meaning:** does a footprint list the files evidence *touched* or the files it *depends on*? Today `authorizeEvidence` (`internal/mcp/tools_evidence.go`) checks every footprint path against the token's write scope, so an agent allowed only `internal/auth/**` cannot declare that its tests also depend on `pkg/crypto/**`. That pushes footprints to be smaller than the truth, and a change to `pkg/crypto` would then leave the evidence `carried` instead of `stale`. Proposal: footprint means *depends on* (FR-4.6); scope limits writes, not dependencies, so footprint paths are validated (C2) but not scope-checked.
