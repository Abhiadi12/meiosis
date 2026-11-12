# Evidence (v1)

**Evidence** is a typed verification result (e.g., a test run, type check, or human review). The central design decision of Meiosis is that Evidence is **strictly bound to a specific WorldHash**, rather than a branch name.

## Purpose & Lifecycle
- **Automatic Expiration:** When the code changes (resulting in a new WorldHash), the proof goes stale automatically unless re-verified or incrementally mapped.
- **Immutability (FR-4.12):** Evidence records are immutable. Corrections or re-runs are submitted as new records superseding the old ones.

## Object Definition

### Core Fields
- `id` (String, required): Unique identifier for the evidence record.
- `attempt` (String, required): The `AttemptID` this evidence is associated with.
- `world` (String, required): The `WorldHash` of the exact tree state that was verified. Evidence *not* bound to a world hash is rejected (FR-4.1).
- `kind` (String, required): The type of evidence. See "Allowed Kinds" below.
- `producer` (String, required): PrincipalID of the entity that ran the verification (e.g., CI runner, human reviewer).
- `supersedes` (String, optional): the `id` of an earlier evidence record this one corrects (FR-4.12). *(Added in v1; optional.)*
- `independent` (Boolean, optional): `true` when `producer != Attempt.author` (see Validation Rules). Computed by the server at submission and stored with the record; a client-supplied value that disagrees with the computed one is rejected. Omitted from the encoding when `false`. *(Added in v1; optional, so existing objects remain valid.)*
- `outcome` (String, required): The result. Allowed values: `"pass"`, `"fail"`, `"inconclusive"`.
- `footprint` (Array of String, optional): The explicit set of paths or symbols this evidence depends on. Each entry is a clean repository-relative path or a doublestar glob (`internal/auth/**`). Symbol entries (`sym:...`) are reserved and rejected for now. The server normalises the list before signing: sorted, without duplicates, and without exact paths already matched by a glob in the list; at most 1,000 entries. An empty or absent footprint means the evidence depends on the whole world.
- `payload` (JSON, required): Kind-specific data (e.g., test coverage percentages, linter output).
- `expires_at` (Timestamp, optional): A TTL after which the evidence expires regardless of footprint (FR-4.11).
- `created_at` (Timestamp, required): ISO8601 timestamp.
- `signature` (Sig, required): Ed25519 signature by the `producer`.

### Payload schemas (FR-4.2)
Every built-in kind has a published JSON Schema for its `payload` in [`schemas/`](schemas/), named `<kind>.schema.json`. A server validates each payload against its kind's schema and rejects a mismatch. The schemas are deliberately permissive: every property is optional, but a property that is present must have the stated type and range, and the payload must be a JSON object. Implementations need support only the keywords `type`, `properties`, `required`, `additionalProperties` (boolean), `items`, `minItems`, `maxItems`, `enum`, `const`, `minimum`, `maximum`, `minLength` and `maxLength`; other keywords are ignored.

### Custom kinds (FR-4.2)
A deployment may register its own kinds. A custom kind is named `x-` followed by lower-case letters, digits and hyphens (starting and ending with a letter or digit, at most 64 characters in all), so it can never collide with a built-in kind added later. Registration is an `EvidenceKindDef` object:
- `kind` (String, required): the `x-` name.
- `schema` (JSON object, required): the JSON Schema its payloads must satisfy.
- `registered_by` (String, required): PrincipalID.
- `registered_at` (Timestamp, required): ISO8601 timestamp.
- `signature` (Sig, required): Ed25519 signature by `registered_by`.

Evidence of a custom kind is accepted only once the kind is registered. Registrations are immutable: registering the same kind with an equivalent schema is a no-op, and a different schema is refused; a changed schema is a new name (for example `x-license-check-v2`).

### Allowed Kinds (FR-4.2)
Built-in values for `kind` include:
- `"test-run"`: Unit/Integration tests.
- `"coverage"`: Code coverage reports.
- `"type-check"`: Compiler type checking.
- `"static-analysis"`: Linting (e.g., `golangci-lint`).
- `"benchmark"`: Performance benchmarks.
- `"mutation"`: Mutation testing results.
- `"security-scan"`: SAST or secret scanning.
- `"replay-match"`: A zygote bundle reproduced exactly (FR-4.9).
- `"human-review"`: A manual human code review.

## Report adapters (FR-4.3)
The reference implementation turns reports that verification tools already produce into evidence, without executing anything: JUnit XML and `go test -json` (kind `test-run`), SARIF (kind `static-analysis`, or `security-scan` / `type-check` when the caller says so), Cobertura XML and LCOV (kind `coverage`), and CycloneDX JSON (kind `security-scan`). The outcome comes from the report, never from the submitter:
- **test-run:** `fail` if any case failed or errored (counted from the cases, not the totals a report declares); `inconclusive` if nothing ran; otherwise `pass`.
- **static-analysis / security-scan (SARIF):** `fail` if any result has level `error` (a missing level counts as `warning`); `inconclusive` if the log has no runs; otherwise `pass`.
- **coverage:** a measurement, recorded as `inconclusive` unless the submitter states a minimum line-coverage percentage, in which case `pass` or `fail` against it. A pass is never implied without a stated bar.
- **CycloneDX:** `fail` if any vulnerability's worst rating is `high` or `critical`; `inconclusive` if the BOM carries no `vulnerabilities` section, since an inventory alone does not show the absence of known vulnerabilities; otherwise `pass`.
Reports are limited to 32 MiB; XML nested more than 64 levels is rejected.

## Validation Rules & Relationships
1. **Independence (FR-4.4):** A core Meiosis property is that an agent cannot grade its own homework. Independence is dynamically computed as: `independent = (Evidence.producer != Attempt.author)`. Policy can mandate independent evidence.
   Because `independent` is part of the signed record, it cannot be altered after the fact. The `producer` is the authenticated principal that signed the record; a server MUST NOT accept a `producer` other than the submitting principal.
2. **Footprint Invalidation (FR-4.7):** If a footprint is provided, Meiosis tracks it. When any file or symbol in the `footprint` changes in subsequent worlds, dependent evidence becomes `stale` automatically without requiring a full re-run.
3. **Freshness:** Evidence is *fresh* only while `Evidence.world` equals the Attempt's current `world`. Evidence submitted for a superseded world is accepted and stored but is reported as stale and never counted.
4. **Superseding (FR-4.12):** A record that sets `supersedes` MUST name an existing record on the same attempt, produced by the same `producer`, that has no successor yet. The earlier record is never altered; it is simply not counted. Only the original producer may correct a record, so an author cannot make an independent party's failure stop counting by "correcting" it with its own record. *Counted* evidence is evidence that is fresh and not superseded.
5. **Attempt Must Be Open:** Evidence is accepted only for an existing attempt whose status is `open`.
6. **World Exclusivity:** Evidence is useless if the `world` hash does not match the Attempt's target or base worlds (or a direct ancestor).
