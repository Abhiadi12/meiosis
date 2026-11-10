# Attempt (v1)

An **Attempt** represents one principal's specific implementation of an `Intent`. It is materialized as a specific state of the repository, represented by a `WorldHash`.

## Purpose & Lifecycle
- **Competitive Attempts (FR-6.6):** Meiosis supports multiple concurrent attempts resolving the same Intent. They are ranked by evidence under policy. When one merges, the others are archived with their evidence intact.
- **Immutability:** Attempts are append-only. The reference implementation stores the attempt as an immutable *creation record* (`world == base_world`, `status == "open"`, no violations) and keeps its changing fields (`world`, `scope_violations`, `status`) in a separate, mutable **state snapshot**: a complete `Attempt` object with the same `id`, `intent`, `author`, `base_world` and `created_at`, signed by the author. The creation record is never rewritten, and a state snapshot that changes any identifying field is rejected. The *current view* of an attempt is its latest state snapshot, or the creation record if there is none.
- **Worlds:** Each commit stores a *world manifest* (path to content digest) addressed by the resulting `WorldHash`; manifests are immutable.

## Object Definition

### Core Fields
- `id` (String, required): AttemptID in the format `"att_{base32(blake3(canonical_json))}"`.
- `intent` (String, required): The `IntentID` this attempt is trying to resolve.
- `author` (String, required): PrincipalID of the author (human or agent).
- `world` (String, required): The 32-byte BLAKE3 `WorldHash` of the implementation's tree state.
- `base_world` (String, required): The `WorldHash` of the base tree this attempt was branched from.
- `forked_from` (String, optional): the `AttemptID` whose workspace state this attempt was forked from (FR-2.3). The fork's operation log continues the source's; see [Operation](operation.md).
- `git_commit` (String, optional): The Git commit hash corresponding to this world state (for Git interop).
- `scope_violations` (Array of Object, optional): If the Intent's scope mode was `"warn"`, any modifications outside the allowed scope are logged here.
- `status` (String, required): Current status. Allowed values include `"open"`, `"merged"`, `"abandoned"`.
- `created_at` (Timestamp, required): ISO8601 timestamp.
- `signature` (Sig, required): Ed25519 signature of the canonical object bytes by the `author`.

## Validation Rules & Relationships
1. **Relationship to Intent:** Every Attempt MUST map to exactly one valid `Intent`.
2. **World Binding:** The `world` field is the definitive identifier of the code's state. Evidence is bound directly to this hash.
3. **Scope Validation:** Upon creation, the server MUST calculate the diff between `base_world` and `world`. It then evaluates this diff against the parent `Intent`'s `Scope`. If the diff violates the scope and the mode is `"enforce"`, the Attempt is rejected. If `"warn"`, the violations are appended to `scope_violations`.
