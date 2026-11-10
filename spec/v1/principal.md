# Principal (v1)

A **Principal** represents an authenticated actor within the Meiosis system. Every mutating operation in Meiosis must trace back to a Principal.

## Definition

- **Format:** String identifier strictly in the format `"{type}:{name}"`.
- **Allowed Types (FR-1.1):**
  - `human` (e.g., `"human:lakin"`)
  - `agent` (e.g., `"agent:planner-7"`)

## Validation Rules & Relationships
1. **Cryptographic Identity:** A Principal is fundamentally bound to an Ed25519 keypair. All objects and mutations authored by a Principal must carry a valid signature that verifies against their public key.
2. **Delegation (FR-1.5):** A Principal may delegate a capability token to a sub-principal (like a spawned agent). This capability MUST be a *strict subset* of its own scope. Any attempt to widen the scope is rejected at issuance.
3. **Traceability (FR-1.6):** Delegation chains are recorded by the system. Given any write by an `agent` Principal, the system must be able to trace the full delegation chain back to the originating `human` Principal.
4. **Revocation (FR-1.7):** Revoking a principal revokes all capabilities delegated from it, transitively.
