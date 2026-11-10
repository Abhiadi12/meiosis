# Attestation (v1)

An **Attestation** is an in-toto-compatible signed provenance record. It securely tracks *how* an attempt was generated, detailing the agent, the AI model used, the tools consumed, and the associated costs.

## Purpose & Lifecycle
- **Provenance:** Every write traces back to an originating human and explicitly logs the machine operations.
- **Auditing:** Useful for review-debt reports, calculating Brier scores per-model, and linking incidents back to specific model versions (FR-7.3).

## Object Definition

### Core Fields
- `attempt` (String, required): The `AttemptID` this attestation corresponds to.
- `agent` (String, required): PrincipalID of the agent that generated the attempt.
- `model` (String, required): AI Model identifier (e.g., `"claude-opus-5"`).
- `model_ver` (String, required): Precise model version or hash.
- `tools` (Array of String, required): List of MCP tools or system commands the agent utilized during generation.
- `prompt_hash` (String, required): The BLAKE3 digest of the prompt used.
- `seed` (Integer, optional): The RNG seed used for the model inference, for reproducibility.
- `params` (Map<String, String>, optional): Inference parameters (e.g., `{"temperature": "0.7"}`).
- `run_bundle` (String, optional): The digest of the `zygote` bundle, enabling deterministic replay of the agent's environment.
- `tokens_in` (Integer, required): Count of prompt tokens.
- `tokens_out` (Integer, required): Count of completion tokens.
- `cost_micros` (Integer, required): Computed cost of the generation in micro-units (for budget and spend ceiling tracking).
- `signature` (Sig, required): Ed25519 signature of the canonical object by the `agent`.

## Validation Rules & Relationships
1. **Prompt Privacy (NFR-4.2):** Prompts routinely contain credentials or sensitive customer data. Therefore, the specification strictly requires storing only the `prompt_hash` by default. Full prompt retention is an opt-in server configuration and not part of the baseline Attestation object.
2. **One Per World:** While an Attempt can have many Evidence records, it has exactly one Attestation per committed `WorldHash`, representing the generation of that specific world. Attestations are immutable: committing again onto an already-attested world keeps the original attestation, and committing a new world records a new attestation without altering earlier ones.
3. **Unreported Fields:** When an agent does not report `model` or `model_ver`, implementations record the literal `"unknown"` rather than inventing a value; an unreported prompt is recorded as the digest of the empty input.
4. **Capability Constraints (FR-1.4):** If the `cost_micros` pushes the agent's principal over its assigned spend ceiling, the write may be rejected.
