# RefUpdate (v1)

A **RefUpdate** records that a Git ref moved, and the **world hash** of the tree the new commit holds (FR-2.2). It is the bridge between the two DAGs the SRS describes (§4.1): the commit DAG that Git tooling reads and the world hashes that evidence is bound to. Records are append-only.

## Object Definition

### Core Fields
- `id` (String, required): `"ref_{base32(blake3(canonical_json))}"`.
- `repo` (String, required): the repository the ref belongs to.
- `ref` (String, required): the full ref name; it MUST begin `refs/`.
- `old_commit` (String, optional): the object ID the ref pointed at before; absent when the push created the ref. A full 40- or 64-character lower-case hex Git object ID.
- `new_commit` (String, required): the object ID the ref points at now (for an annotated tag, the tag object).
- `world` (WorldHash, required): the hash of the tree at `new_commit`.
- `base_world` (WorldHash, optional): the hash of the tree at `old_commit`. Present exactly when `old_commit` is.
- `pushed_by` (String, required): the PrincipalID that pushed. `human:anonymous` when the server accepted the push without authentication.
- `token` (CapabilityToken, optional): the capability token, with its delegation chain, the push was made under. Absent for an unauthenticated push.
- `intent` (String, required): the IntentID the push is under.
- `implicit_intent` (Boolean, optional): `true` when the push named no intent and the server derived one with scope mode `"warn"` (IF-1).
- `attempt` (String, optional): an existing attempt on the same intent whose world equals `world`: the push delivered the tree that attempt produced.
- `changed_paths` (Integer, required): how many paths the pushed commits changed. Deleted paths count.
- `scope_violations` (Array, optional): paths outside the intent's scope accepted because its mode is `"warn"`.
- `at` (Timestamp, required).
- `signed_by` (String, required): the PrincipalID of the server that observed the push.
- `signature` (Sig, required): Ed25519 signature by `signed_by`.

## Rules

1. **The world hash is the same hash.** `world` is computed exactly as the world of an attempt: BLAKE3 over the tree's files in path order, each as length-prefixed path and length-prefixed content. File modes are not part of a world. A submodule contributes its commit ID. The same files therefore hash identically whether they arrived through an attempt or through `git push`, which is what lets `attempt` be found by equality.
2. **Whose signature.** The pusher authenticates with a bearer token, not a key, so the record is signed by the server, which vouches for what it observed; `pushed_by` and `token` say who asked and under what authority. The record is therefore *server-attested*, not self-signed by the pusher.
3. **Policy at push time (FR-3.4).** Before a ref moves, a conforming server refuses the push when any changed path is outside the token's scope, or outside the scope of the intent the push is under when that intent's mode is `"enforce"`. The intent is the one the push names (the `intent` push option) or the one its token is bound to; naming one that differs from the token's is refused, as is naming one that is unknown or no longer open. In `"warn"` mode the push is accepted and the paths recorded in `scope_violations`.
4. **No rewriting.** A conforming server does not accept deleting a ref or a non-fast-forward update, so every record has a `new_commit` and a world.
5. **After the move.** The record is written after the ref has moved. If recording fails the pusher is told, and the ref has still moved; a server may reconstruct the record from the repository.

## Secret scan fields (NFR-4.4)

A server that scans pushes for credentials records the outcome with these optional fields:

- `secret_scan` (String): `"off"`, `"warn"` or `"block"`, the mode in force.
- `secret_findings` (Array of `{path, line?, rule, confidence}`): `confidence` is `"high"` or `"possible"`. A finding **names the place and the rule, never the secret value**. `line` is 0 when the finding concerns the path itself.
- `secret_scan_truncated` (Boolean): the scan stopped at a size limit.

In `"block"` mode a push with a high-confidence finding is refused and no record is created. The scan is a tripwire, not a guarantee.
