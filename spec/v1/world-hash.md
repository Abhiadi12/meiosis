# WorldHash (v1)

A **WorldHash** represents the complete, content-addressed state of a repository tree at a specific point in time. It is the fundamental anchor for all proofs and attempts in Meiosis.

## Definition

- **Format:** A 32-byte BLAKE3 root hash of the repository tree, serialized as a 64-character hexadecimal string in JSON.

## Validation Rules & Relationships
1. **Deterministic Hashing:** Two identical repository trees MUST always hash to the exact same `WorldHash`. Meiosis relies on BLAKE3 tree-hashing to efficiently compute Merkle worlds.
2. **Evidence Binding (FR-4.1):** All `Evidence` records in Meiosis are strictly bound to a `WorldHash`. Evidence is never bound to a branch name, PR, or intent ID directly. 
3. **Immutability of Proof:** If the codebase changes by even a single byte, the new tree yields a new `WorldHash`. This architectural rule ensures that evidence bound to the old `WorldHash` naturally and automatically goes stale, preventing "green check" drift.

## Exact encoding

The hash is BLAKE3-256 over the concatenation, for every file in **ascending byte order of path** (UTF-8 bytes, no normalisation), of:

```
u64be(len(path)) || path || u64be(len(content)) || content
```

File modes are not hashed; the empty tree hashes the empty input. Known-answer vectors are in `spec/conformance/vectors/world-hashes.json`.
