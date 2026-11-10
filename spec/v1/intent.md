# Intent (v1)

An **Intent** is the primary unit of desired change within Meiosis. Instead of reviewing diffs in isolation, Meiosis tracks the explicitly declared goal, scope, and acceptance criteria *before* or *alongside* the code changes.

## Purpose & Lifecycle
- **Immutability:** An Intent is immutable once created and signed. Any modifications to the goal, scope, or criteria are made by creating a new Intent with a `SupersededBy` pointer on the predecessor (FR-3.2).
- **Status:** The lifecycle is tracked via status transitions: `open` -> `attempting` -> `merged` (or `abandoned` / `stale`). Because the Intent itself never changes, its *current* status and any supersession live in a separate [IntentState](#intentstate) record; the `status` field on the Intent is the status at creation. Opening the first attempt on an `open` intent moves it to `attempting`.
- **Supersession (FR-3.2):** A superseded intent is left exactly as it was. Its IntentState records `superseded_by`, and it accepts no new attempts. An intent can be superseded once, and not once `merged`.
- **Derived intents (FR-3.8):** Implementations SHOULD let an agent supply only a task description and derive the intent from it: the title is the task's first line (at most 80 characters), the goal is the full task, there is one acceptance criterion, and the scope is the authority the agent already holds. Deriving the same task again for the same principal, repo and scope reuses the existing open intent.

## Object Definition

### Core Fields
- `id` (String, required): IntentID in the format `"int_{base32(blake3(canonical_json))}"`.
- `repo` (String, required): The repository identifier this intent applies to.
- `title` (String, required): Human-readable title of the intent.
- `goal` (String, required): Detailed description of the goal to be achieved.
- `acceptance` (Array of `Criterion`, required): The conditions that must be met for this intent to be merged.
- `non_goals` (Array of String, optional): Explicit non-goals to bound the work.
- `scope` (`Scope`, required): Declared paths the attempt is allowed to touch.
- `context_pins` (Array of `ContextPin`, optional): Pinned context documents that the author consumed.
- `parent` (String, optional): IntentID of the parent intent (if this is a sub-task).
- `depends_on` (Array of String, optional): IntentIDs that must be merged before this intent can be merged.
- `created_by` (String, required): PrincipalID of the creator (human or agent).
- `created_at` (Timestamp, required): ISO8601 timestamp of creation.
- `status` (String, required): Current status. Allowed values: `"open"`, `"attempting"`, `"merged"`, `"abandoned"`, `"stale"`.
- `signature` (Sig, required): Ed25519 signature of the canonical object bytes.

### Sub-objects

#### Criterion
Criteria can be textual or machine-checkable.
- `text` (String, required): Human-readable description.
- `check` (Object, optional): Machine-checkable definition (e.g., `{"kind":"test","selector":"./pkg/auth/..."}`).

#### Scope
Scope enforces what files an attempt is allowed to modify (FR-3.4).
- `allow` (Array of String, required): Glob patterns allowed to be modified.
- `deny` (Array of String, optional): Glob patterns strictly denied.
- `mode` (String, required): `"enforce"` (reject the write if it violates scope) or `"warn"` (allow the commit but flag as a violation).

#### ContextPin
Pins the exact version of documentation/issues the author used to write the code.
- `ref` (String, required): Path, URL, or issue ID.
- `digest` (String, required): BLAKE3 digest of the content at the time of consumption.
- `kind` (String, required): Allowed values: `"spec"`, `"adr"`, `"issue"`, `"design"`, `"convention"`.

#### IntentState
The mutable lifecycle state of one Intent, signed by the principal who made the change. Keyed by `intent`; the latest record is current.
- `intent` (String, required): the IntentID.
- `status` (String, required): one of the Intent statuses.
- `superseded_by` (String, optional): the successor IntentID. Must differ from `intent`.
- `updated_by` (String, required): PrincipalID that made the change.
- `updated_at` (Timestamp, required): ISO8601 timestamp.
- `signature` (Sig, required): Ed25519 signature by `updated_by`.

## Validation Rules & Relationships
1. **DAG Cycles:** Intents can form a Directed Acyclic Graph via the `depends_on` array (and `parent`). The system MUST reject any cycles. Every referenced intent MUST exist. Since an intent ID is derived from content that includes its references, a cycle cannot arise among already-stored intents; it can arise through supersession, because a successor stands in for its predecessor. A successor therefore MUST NOT depend, directly or transitively, on the intent it supersedes.
2. **Scope Enforcement:** Depending on `scope.mode`, attempts that modify files outside the `allow` globs must be either hard-rejected at push time, or recorded with a scope violation.
3. **Context Pins (FR-3.5):** `digest` is the lower-case hex BLAKE3-256 digest of the document's bytes exactly as consumed. A pin whose `ref` is a repo-relative path can be re-checked by re-hashing the file: a different digest, or a missing file, means the pin has changed. Refs that are URLs or issue ids cannot be re-checked locally and are reported as unchecked, never as matching.
4. **Context Freshness (FR-3.6):** If a document referenced in `context_pins` changes (its content digest no longer matches `digest`), all attempts and merged intents depending on this Intent transition to `stale`.
