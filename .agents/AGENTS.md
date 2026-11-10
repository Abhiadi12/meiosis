# Meiosis MCP tools

This repository is governed by meiosis — source control where evidence
expires. The daemon (meiosisd) exposes its tools over MCP; any agent in this
workspace may call them.

## MCP server

- server: meiosisd (registered in the IDE global MCP config)
- tools: attempt_open, attempt_write, attempt_commit, attempt_status, evidence_ingest, evidence_submit,
  intent_create, intent_get, intent_list, intent_supersede, intent_check_path,
  capability_delegate, authority_chain, evidence_query, workspace_fork, workspace_diff,
  workspace_oplog, workspace_undo

## Mandatory rule: every tool call must carry a capability token

The daemon runs with capability enforcement ON. A call whose arguments object
lacks a `capability_token` field is rejected. Read the token from
.agents/meiosis-capability.json (relative to the repo root) and embed it as a JSON object, not a string.

For intent_check_path and evidence_submit the token must also cover the exact
path/paths you pass. This token's scope — allows: ** ; denies: (none) — is enforced there and at any
real write path. If a call is rejected for a path, do not retry: it is out of
scope by design. Ask the human to issue a wider token with:
    mei intent authorize --issuer human:<you> --allow '<glob>' ...

## Workflow

1. `attempt_open` starts work. Pass just your `task` (what you were asked to do)
   and an intent is derived for you from it, with the scope you were granted; you
   never have to write one. Pass an existing `intent` ID instead to work under
   an intent a human declared.
2. `intent_create` / `intent_supersede` are only for when you need to declare
   an intent explicitly or replace one (intents are immutable: the old one stays,
   records its successor, and takes no new attempts). `intent_get` and
   `intent_list` read them.
3. `attempt_write` writes (or deletes) files in the attempt. The path is checked
   against the intent's scope when you write, not at review: in `enforce` mode an
   out-of-scope write is rejected and nothing is stored; in `warn` mode it is
   stored and recorded as a scope violation. Never retry a rejected path.
4. `attempt_commit` snapshots the attempt into a world hash and records signed
   provenance. Report your `model`, `model_ver`, `tools` and `prompt` (only its
   digest is kept) and your token usage; anything you omit is recorded as unknown.
5. `evidence_ingest` turns a report your tools produced (JUnit XML, go test -json,
   SARIF, Cobertura, LCOV, CycloneDX JSON) into signed evidence bound to the
   committed world. Pass the report text; the outcome comes from the report, not
   from you. Commit first. `evidence_submit` records a result with no adapter.
   Evidence you produce about your own attempt is marked not independent. To
   correct a record of yours, submit a new one with `supersedes`.
6. `attempt_status` shows the attempt, its provenance and its evidence, and which
   evidence is still fresh.
7. `evidence_query` lists evidence on an attempt, filtered by kind, outcome or
   freshness, without fetching every record.
8. `workspace_fork` starts a new attempt from the current state of one of your
   attempts (instant, whatever its size), to try an alternative. `workspace_diff`
   shows what an attempt changed against its base as a unified diff that
   `git apply` accepts. `workspace_oplog` lists every write, commit and undo.
   `workspace_undo` reverts one operation (a commit restores the previous world
   exactly); it refuses when later work depends on it.
9. Any mutating tool accepts an `idempotency_key`: retrying with the same key and
   arguments returns the first result instead of repeating the work. Use one when
   a call may have timed out.

A human can see and steer the same state with `mei work status`, `mei work fork`,
`mei op log` and `mei op undo`.

## Pushing with git

You can also deliver work with plain git to the server (`mei serve`). Authenticate
with your capability token as a bearer header:

    git -c http.extraHeader="Authorization: Bearer $(mei token bearer)" push meiosis main

Add `-o intent=<intent id>` to push under a declared intent: every path the push
changes must then be inside that intent's scope, or the push is refused and nothing
moves. A push that names no intent is accepted under an implicit one. Do not delete
refs or rewrite history; both are refused.

## Delegating to a sub-agent

If you start a sub-agent, give it part of your authority with `capability_delegate`:
pass its `principal` and its public key as `holder_key`, and optionally a narrower
`scope`, a list of `operations`, a `spend_ceiling_micros` and a `ttl_seconds`. What you
hand over can only be a subset of what you hold; asking for more is refused. The
sub-agent runs with its own key and presents the token you get back. Its writes are
recorded with the chain behind them, and `authority_chain` shows it. Cost it reports
counts against your own spend ceiling too. Your token may limit the tools you can
call; a call outside that list is refused.

## Example

Call intent_create with:

{
  "repo": ".",
  "title": "Refactor UI component",
  "goal": "Update the Button component safely",
  "acceptance": [{"text": "Component tests pass"}],
  "scope": {"allow": ["src/components/**"], "deny": ["pkg/auth/**"], "mode": "enforce"},
  "`capability_token`": <object from .agents/meiosis-capability.json>
}
