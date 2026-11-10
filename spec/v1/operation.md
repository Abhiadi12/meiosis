# Operation (v1)

An **Operation** is one entry in a workspace's operation log (FR-2.5). The log of an attempt is append-only and every entry is signed by the principal that made it, so a workspace's history, including its undos, can be audited and replayed.

## State model

A workspace's state is an *overlay* on its attempt's `base_world`: a map from path to blob ID, where the empty string means "deleted" and an absent path means "as in the base". The state at an operation is the overlay after applying the log up to it. Every `SnapshotInterval` (32) operations an operation carries a full `snapshot` of the overlay, so reading the state needs at most 32 entries.

## Object definition

- `id` (required): `"op_{base32(blake3(canonical_json))}"`.
- `attempt` (required): the owning `AttemptID`.
- `kind` (required): `open`, `write`, `delete`, `commit`, `fork` or `revert`.
- `seq` (required, >= 0): distance from the start of the lineage; it continues across a fork.
- `parent` (optional): the previous operation. Exactly the first operation of a lineage (`seq == 0`) has none.
- `path`, `blob`: for `write` / `delete`, and for the file a `revert` restores. `blob` is the blob ID of the content.
- `unset` (optional bool): on a revert, return `path` to its base-world state (no overlay entry), as opposed to an empty `blob`, which means deleted.
- `reverts` (optional): the operation a `revert` undoes.
- `forked_from` (optional): the attempt a `fork` was taken from.
- `world`, `prev_world` (optional): for a `commit`, the world produced and the world before; for a `revert` of a commit, the world restored.
- `snapshot` (optional): the complete overlay after this operation.
- `by` (required): the principal. `at` (required): server timestamp. `signature` (required): Ed25519 over the canonical unsigned object.

## Rules

1. **Fork is O(1).** Forking appends one `fork` operation whose `parent` is the source's latest operation; nothing is copied, whatever the size of the tree.
2. **Undo appends.** A `revert` is a new operation; nothing is removed. Reverting a write or delete restores the path's previous state; reverting a commit restores the exact prior `world`, so a world hash can always be returned to.
3. **Only the latest effect can be undone** if later operations touched the same path or world; otherwise the server refuses (`not undoable`) rather than guess.
4. **A server timestamps** every operation; a client-supplied `at` is ignored.
