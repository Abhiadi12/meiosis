# Verdict (v1)

A **Verdict** records a merge decision and everything that produced it. It acts as the final historical record of a repository modification via Meiosis. 

## Purpose & Lifecycle
- **Traceability:** If a human cannot understand why an agent's code merged, the system has failed. The Verdict ensures the exact policy, inputs, and rationale are durably logged (FR-5.8).
- **Append-Only:** Verdicts are append-only into the audit log.

## Object Definition

### Core Fields
- `attempt` (String, required): The `AttemptID` this verdict applies to.
- `decision` (String, required): The final outcome. Allowed values: `"merge"`, `"reject"`, `"escalate"`.
- `decided_by` (String, required): PrincipalID of the entity that made the decision (e.g., a human reviewer, or the automated policy engine principal).
- `policy_ref` (String, required): The path and content digest of the Rego policy used to make the decision (e.g., `.meiosis/policy/default.rego @ 7c1a9e`).
- `policy_in` (JSON, required): The *exact* JSON input document that was fed into the Rego policy engine.
- `risk` (Object, required): The computed risk score at the time of evaluation.
- `confidence` (Float, optional): Computed confidence level of the agent/system.
- `rationale` (String, required): Human-readable rationale for the decision.
- `decided_at` (Timestamp, required): ISO8601 timestamp.
- `signature` (Sig, required): Ed25519 signature of the canonical object by `decided_by`.

### Sub-objects

#### Risk Object (FR-5.2)
Risk is computed dynamically based on the attempt's diff footprint.
- `blast_radius` (Integer): The number of symbols/modules transitively reachable from the change.
- `sensitive_paths` (Array of String): List of touched paths that are flagged as sensitive (e.g., `auth/`, `crypto/`).
- `incident_density` (Float): Historical incident rate of the touched modules.

## Validation Rules & Relationships
1. **Immutable Inputs (FR-5.8):** A Verdict MUST embed the exact `policy_in` JSON document. This ensures that even if Evidence expires or policies change later, an auditor can perfectly replay the exact state that resulted in the `"merge"` decision.
2. **Policy Compilation:** The system guarantees that if the policy referenced in `policy_ref` fails to compile or evaluate, the decision forcefully defaults to `"escalate"`, rather than defaulting open.
