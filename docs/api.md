# The JSON API (IF-2)

`mei serve` exposes every agent operation as plain JSON over HTTP, for clients
that are not MCP clients. It is the same code as the MCP tools (same checks, same
errors), so there is nothing the API can do that a tool cannot.

> **Not provided: ConnectRPC / gRPC.** The SRS names ConnectRPC with protobuf
> schemas. That needs code generation and several modules beyond the dependency
> budget, so M1 offers this JSON API instead. It has the properties IF-2 asks for
> (below). It can be replaced by, or supplemented with, ConnectRPC without
> changing the operations.

## Endpoints

```
GET  /api/v1/tools              the operations, each with its JSON input schema
POST /api/v1/tools/{name}       run one; the body is its arguments (a JSON object)
```

Authentication is a capability token: `Authorization: Bearer <token>` (as printed
by `mei token bearer`), or a `capability_token` member in the body.

## The three IF-2 properties

- **Non-interactive.** No operation prompts, asks for a TTY or waits for input.
- **Transactional.** A mutation is applied whole or not at all. Each write is one
  database transaction; a refused write (scope, token, validation) leaves nothing
  behind. One caveat: the *authority record* of a write is appended just after it
  (see `docs/threat-model.md`).
- **Idempotent.** Send `Idempotency-Key: <key>` (or an `idempotency_key` member)
  on any mutating operation. A retry with the same key and the same arguments
  returns the first call's result with `"idempotent_replay": true` and does the
  work once; the same key with different arguments is `409`. The key is scoped to
  the principal and the operation. Only successes are remembered, so a failed call
  can be retried under the same key. Credentials are not part of the comparison, so
  a retry with a refreshed token is still a retry, but a replay still needs a valid
  token. Exactly-once holds within one server process; two processes sharing a
  database do not coordinate.

## Responses

Success: `200 {"result": …, "idempotent_replay": false}`.
Failure: `{"error": {"code": "…", "message": "…"}}` with a status:

| status | code | meaning |
|---|---|---|
| 400 | `invalid_json`, `invalid_request` | the body or an argument is malformed |
| 401 | `unauthenticated`, `invalid_token` | no token, or it is expired, revoked, altered or unreadable (sends `WWW-Authenticate: Bearer`) |
| 403 | `forbidden` | the token is valid but does not permit this: scope, operation, intent, principal, authorship, spend ceiling, widening a delegation |
| 404 | `not_found`, `unknown_tool` | no such operation, attempt, intent or evidence |
| 409 | `conflict` | the state forbids it: already superseded, immutable, closed intent, not undoable, idempotency key reused |
| 422 | `invalid` | well-formed but rejected: a payload that fails its kind's schema, a dependency cycle |
| 500 | `internal` | a bug or a storage failure |

Requests naming a different `Origin` are refused (403). Bodies are limited to 16 MiB.

## Example

```sh
curl -sS -X POST http://127.0.0.1:8484/api/v1/tools/attempt_open \
  -H "Authorization: Bearer $(mei token bearer)" \
  -H "Idempotency-Key: open-login-fix-1" \
  -d '{"task": "Fix the login redirect"}'
```
