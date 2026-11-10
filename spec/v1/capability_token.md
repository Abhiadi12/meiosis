# CapabilityToken (v1)

A **CapabilityToken** grants a Principal a narrow, time-bounded permission to
operate within an Intent's declared scope. It is the credential a Principal
presents before a write is admitted (FR-1.3/FR-1.4); `Intent.scope` is still
enforced separately at commit time (FR-3.4).

The token is signed by the issuing Principal, not the holder: `principal` is
who the capability is granted to, `issued_by` is who granted it and whose key
produced `signature`. A Principal can therefore never mint or widen its own
authority — it can only be delegated a subset of what an issuer already holds
(FR-1.5).

## Object Definition

### Core Fields
- `id` (String, required): `CapabilityTokenID` in the format `"cap_{base32(32 random bytes)}"`. Unlike `IntentID`/`AttemptID`, this ID is **random, not content-derived** — two tokens issued with otherwise identical fields still need independent identities so that one can be revoked without affecting the other.
- `principal` (String, required): `PrincipalID` the capability is granted to (the holder).
- `issued_by` (String, required): `PrincipalID` granting the capability (the issuer). Signs the token.
- `intent` (String, required): `IntentID` this capability is scoped to. A token bound to an intent may act only on that intent. The reserved value `int_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (`int_` followed by 52 `a`) marks a **repository-level token**, bound to no single intent: it may act on any intent within its path `scope` and is the only kind that may create new intents. *(Clarified in v1; the field and its format are unchanged.)*
- `scope` (Object, required): Path glob constraints, same shape as `Intent.scope` (`allow`, `deny`, `mode`). `deny` overrides `allow`.
- `issued_at` (Timestamp, required): ISO8601 timestamp.
- `expires_at` (Timestamp, required): ISO8601 timestamp. Must be strictly after `issued_at`.
- `holder_key` (String, optional): the holder's Ed25519 public key, base64, asserted by the issuer. A token without one cannot be delegated. *(Added in v1; optional.)*
- `operations` (Array of String, optional): the operations the token permits (FR-1.4): any of `intent_create`, `intent_get`, `intent_list`, `intent_supersede`, `intent_check_path`, `attempt_open`, `attempt_write`, `attempt_commit`, `attempt_status`, `evidence_submit`, `evidence_ingest`, `capability_delegate`, `authority_chain`, `evidence_query`, `workspace_fork`, `workspace_diff`, `workspace_oplog`, `workspace_undo`, `git_fetch`, `git_push`. Absent, empty or `["*"]` means all. Names must be known and unique.
- `spend_ceiling_micros` (Integer, optional): the most cost, in micro-units, that commits under this token and anything delegated from it may report (FR-1.4). Absent means no ceiling; `0` means none may be spent. Must not be negative.
- `parent` (CapabilityToken, optional): the token this one was delegated from, embedded whole (FR-1.5, FR-1.6). A root token has none. Delegation may stack at most 8 deep.
- `signature` (Sig, required): Ed25519 signature by `issued_by`. For a delegated token `issued_by` is the parent's `principal` and the signature is made with the parent's `holder_key`; because `parent` is part of the signed bytes, the child is bound to that exact parent.

## Validation Rules & Relationships

1. **Issuer-Signs, Not Holder (FR-1.5):** The signature is produced by `issued_by`'s key, never `principal`'s. This is what makes self-escalation structurally impossible — a Principal cannot mint or widen its own authority, only receive a delegated subset of what an issuer already holds.
2. **Expiry Ordering:** `expires_at` must be strictly after `issued_at`; a token with `expires_at <= issued_at` is invalid.
3. **Short-Lived by Default (NFR-4.3):** Implementations should default new tokens to a short TTL (the reference implementation defaults to one hour).
4. **Revocation (FR-1.7):** A token's `id` may be revoked independently of any other token, including ones issued to the same principal with identical fields — this is the reason `id` is random rather than content-derived. Revoking a Principal revokes all capabilities delegated from it, transitively.
5. **Principal Binding:** A server MUST refuse a token presented by a principal other than the one named in `principal`.
6. **Intent Binding:** A server MUST refuse a token bound to intent A when it is used on intent B, unless it is a repository-level token.
7. **Delegation (FR-1.5):** A token's holder may delegate to a sub-principal by issuing a token whose `parent` is its own. The delegated token may hold only a subset of the parent's authority on every axis: it stays bound to the parent's intent (a repository-level parent may bind a child to one intent); every `scope.allow` pattern lies within the parent's allow set; every parent `scope.deny` pattern is also denied; the scope mode is not relaxed from `enforce`; `operations` are a subset (a restricted parent cannot give `*`); a parent with a `spend_ceiling_micros` requires the child to have one no larger; and `expires_at` is no later than the parent's. Whether one glob lies within another is decided conservatively: an implementation MUST refuse a delegation it cannot show to be narrowing. A holder may delegate only if its token's `operations` include `capability_delegate`.
8. **Verifying a chain (FR-1.5, FR-1.6, FR-1.7):** A verifier trusts only the root issuer's key. For every link from the root down it MUST check the signature (the root against the issuer key; each delegated token against its parent's `holder_key`), that `issued_by` equals the parent's `principal`, that the link narrows its parent as above, that it has not expired and has not been revoked. The root's `issued_by` MUST be a `human:` principal, so a chain always ends at the originating human. Checking narrowing at verification, not only at issuance, means a delegator that signs a wider token by hand gains nothing. Revoking a token therefore revokes everything delegated from it. 
9. **Spend (FR-1.4):** Cost reported at commit is charged against the `spend_ceiling_micros` of the token used and of every ancestor that has one; a commit that would pass any ceiling is refused whole. A recommit onto an already-attested world is not charged again.
10. **Scope Is Independent of Intent.scope:** A capability token's own `scope` is evaluated at authorization time (deny-first, then allow, default-deny) against the *token's* grant. This is a distinct check from the Intent's own declared scope enforcement (FR-3.4) — a real write path evaluates both.

## AuthorityRecord

An append-only record of one write and the capability chain it was made under (FR-1.6). Given any write, the chain back to the originating human is the embedded token's chain.

- `id` (String, required): `"aut_{base32(blake3(canonical_json))}"`.
- `op` (String, required): the operation (one of the names above).
- `principal` (String, required): who made the write.
- `token` (CapabilityToken, required): the token presented, with its whole `parent` chain.
- `object` (String, optional): the ID of what was created or changed.
- `attempt` (String, optional): the attempt it concerns.
- `intent` (String, optional): the intent it concerns.
- `path` (String, optional): the path written.
- `at` (Timestamp, required): when.
- `signature` (Sig, required): Ed25519 signature by `principal`.

A chain recorded in an AuthorityRecord is verified as of `at`, so a token that has since expired still verifies for the write it authorised. The record is written after the write it describes; a failure to record is reported to the caller rather than hidden.
