# Meiosis Format Specification (v1)

This document defines the language-agnostic `v1` format specification for Meiosis core objects. 

As defined in the SRS (§4.3), every object is serialized as JSON and **must** adhere to the [JSON Canonicalization Scheme (RFC 8785)](https://tools.ietf.org/html/rfc8785) for hashing and signing. Two compatible implementations must produce byte-identical canonical forms for the same logical object.

## 1. Core Types Overview

- `PrincipalID`: String format `"{type}:{name}"` (e.g. `"agent:planner-7"` or `"human:lakin"`).
- `IntentID`: String format `"int_{base32(blake3(canonical_json))}"`.
- `AttemptID`: String format `"att_{base32(blake3(canonical_json))}"`.
- `CapabilityTokenID`: String format `"cap_{base32(32 random bytes)}"` — random, not content-derived (see [CapabilityToken](capability_token.md)).
- `WorldHash`: 32-byte BLAKE3 root hash of a repository tree (represented as a hex string in JSON).
- `Sig`: Cryptographic signature (base64 encoded Ed25519 signature over the canonical JSON bytes).

## 2. Core Objects

The detailed definitions for each core object are broken down into the following specifications:

- [Principal](principal.md): An authenticated actor (human or agent).
- [WorldHash](world-hash.md): Content-addressed state of a repository tree.
- [Intent](intent.md): The unit of desired change, and its mutable `IntentState`.
- [Attempt](attempt.md): One principal's implementation of an intent.
- [Evidence](evidence.md): A typed verification result strictly bound to a specific WorldHash, its per-kind payload [schemas](schemas/) and registered custom kinds.
- [Attestation](attestation.md): In-toto-compatible signed provenance of an attempt.
- [RefUpdate](ref_update.md): A Git ref move and the world hash of the tree it produced.
- [Verdict](verdict.md): A recorded merge decision and everything that produced it.
- [CapabilityToken](capability_token.md): A signed, time-bounded, path-scoped permission grant that can be delegated (narrowing only), and the `AuthorityRecord` of each write.

## 3. Relationships and Validation Rules

1. **Immutability:** Intents, Attempts, Evidence, Attestations, Verdicts, and CapabilityTokens are strictly immutable once signed. Any modification is achieved by creating a new object that supersedes the old one (or, for CapabilityTokens, by revoking the old one — see [CapabilityToken](capability_token.md)).
2. **Signature Validation:** Every mutation carries a signature by the relevant principal. The system must reject unverifiable signatures. Signatures must evaluate over the RFC 8785 canonical bytes of the object.
3. **Evidence Independence:** Evidence is computationally "independent" if and only if `Evidence.producer != Attempt.author`.
4. **Evidence Freshness:** Evidence is tightly bound to `Evidence.world`. If the underlying world hash changes, or if a path defined in `Evidence.footprint` changes, the evidence automatically transitions to `stale`.
5. **Context Pin Invalidation:** When the BLAKE3 digest of a document pinned in `Intent.context_pins` changes, all attempts and merged intents depending on it automatically transition to `stale`.
6. **DAG Cycles:** Intents form a DAG via `depends_on`. Cyclical dependencies must be rejected by the system.

## 4. Versioning and Compatibility

The `spec/v1` format is versioned independently of the server implementation (NFR-6.3) and maintains a strict compatibility policy as defined in SRS §9:

1. **Forward Compatibility:** Within the `v1` format, new optional fields may be added to objects at any time. Client implementations MUST ignore unrecognized fields.
2. **Breaking Changes:** Required fields MUST NOT be removed or retyped. Any change that removes a field or alters the fundamental object structure will necessitate a bump to `v2`.
3. **Serialization:** All objects are serialized via JSON over the wire and MUST adhere to RFC 8785 JSON Canonicalization Scheme for cryptographic signatures.

## 5. Changelog

Changes to the `v1` format. Within `v1` only optional fields may be added and required fields may not be removed or retyped (SRS §9, NFR-6.3).

- **v1 (unreleased, additive):**
  - `Evidence.independent` (optional boolean) added: the stored result of `producer != Attempt.author`.
  - `CapabilityToken.intent` clarified: a reserved all-`a` intent ID denotes a repository-level token.
  - `RefUpdate` object added: a Git ref move with the world hash of the new tree, the pusher, the capability chain and the intent (FR-2.2, IF-1). Capability operations `git_fetch` and `git_push` added.
  - `CapabilityToken` gained optional `holder_key`, `operations`, `spend_ceiling_micros` and `parent` (FR-1.4, FR-1.5): delegation chains that can only narrow, verified from the root issuer's key alone. New `AuthorityRecord` object recording the chain behind each write (FR-1.6).
  - `Evidence.supersedes` (optional string) added, for correcting a record without altering it (FR-4.12).
  - Custom evidence kinds added: `x-NAME` kinds, registered with an `EvidenceKindDef` carrying a payload JSON Schema (FR-4.2). Published per-kind payload schemas for the built-in kinds in `schemas/`.
  - Report adapters described, including how each derives its outcome (FR-4.3).
  - `IntentState` object added: the mutable status and `superseded_by` of an otherwise immutable Intent (FR-3.2).
  - Intent rules clarified: `parent`/`depends_on` must reference existing intents and may not form a cycle through supersession; context-pin digest and re-check semantics defined; derived intents described.
  - Attempt storage clarified: immutable creation record plus a separate signed state snapshot; world manifests and per-world attestations are immutable.
  - `Operation` object added: the signed, append-only log of a workspace, with periodic snapshots (FR-2.3, FR-2.5, FR-2.6). `Attempt.forked_from` (optional) added. Capability operations `evidence_query`, `workspace_fork`, `workspace_diff`, `workspace_oplog`, `workspace_undo` added.
  - `RefUpdate` gained optional `secret_scan`, `secret_findings` and `secret_scan_truncated` (NFR-4.4).
  - World-hash byte encoding written out exactly. Known-answer conformance vectors added for canonical JSON, signatures, content IDs and world hashes, with an independent Python verifier.
