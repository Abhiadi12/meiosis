# Operating meiosis

One binary, one directory, SQLite. Nothing here needs an external service.

## What lives where

```
<repo>/.meiosis/
  meiosisd.db            the object graph (SQLite, WAL mode)
  git/NAME.git/          bare repositories served by `mei serve`
  human.private.key      signs intents, tokens, ref updates  (SECRET)
  human.public.key       the trusted issuer key
  agent.private.key      the agent's signing key              (SECRET)
  agent.public.key
  config.yaml            repo: . / format / strict / secrets
<repo>/.agents/
  meiosis-capability.json   the agent's token (a credential)  (SECRET)
  AGENTS.md
```

`mei init` adds the secrets to `.gitignore`. Keep them out of version control.

## First run

```sh
mei serve        # sets the repository up if needed, then serves git + MCP + API
```

Serves `http://127.0.0.1:8484/NAME.git` (git), `/mcp` (MCP over HTTP), `/api/v1/`
(JSON API) and `/metrics` (Prometheus, loopback clients only). Bind to anything but
loopback only behind TLS: tokens are bearer credentials.

## Configuration

`.meiosis/config.yaml`:

| key | values | meaning |
|---|---|---|
| `strict` | `true` (default after init) / `false` | `true` forbids running without capability tokens, and `--allow-unauthenticated` is refused |
| `secrets` | `warn` (default) / `block` / `off` | credential scanning of pushes; `block` refuses high-confidence matches |

Flags override config; `mei serve --help` lists them.

## Backup and restore (NFR-3.3)

```sh
mei backup /backups/meiosis-2026-11-10            # safe while the server runs
mei backup /backups/with-keys --include-keys       # also copies private keys: protect it
mei restore /backups/meiosis-2026-11-10 --repo /srv/project
```

A backup holds a snapshot of the database taken in one transaction, a mirror
clone of each served repository, the config and a manifest with the database's
SHA-256. `restore` verifies the checksum and SQLite's integrity check before it
changes anything, and will not overwrite an existing database without `--force`.

**Do not copy `meiosisd.db` while the server is running.** In WAL mode the
database is the `.db`, `.db-wal` and `.db-shm` files together, and a file copy
can catch them out of step. `mei backup` (or `sqlite3 meiosisd.db ".backup FILE"`)
does not.

**Keys are not in a backup unless you ask.** Without them a restored server
keeps every record, and tokens and signatures stay verifiable from the public
keys, but it cannot sign anything new. Store the private keys separately.

After a restore, start the server and check `mei status` and `mei refs`.
(Replaying the audit log to prove a restore reproduced the same graph, NFR-3.4,
needs the audit log, which is M3.)

## Upgrades

Schema migrations run on start and only add tables; there is no downgrade. Take
a backup first. A release states the oldest version it can upgrade from.

## Monitoring

`GET /metrics` (loopback only unless `MetricsRemote` is set in code) exposes, in
Prometheus text format: `meiosis_up`, `meiosis_build_info{version}`,
`meiosis_http_requests_total{route,code}`,
`meiosis_http_request_duration_seconds{route}`,
`meiosis_tool_calls_total{tool,outcome}` and
`meiosis_tool_call_duration_seconds{tool}`. Label values come from a fixed set;
nothing a client sends becomes a label.

Logs are structured (`log/slog`, text) on standard error. **Not provided:**
OpenTelemetry traces (NFR-5.5), and metrics for pushes (they are handled by git
hooks, separate processes; use `mei refs`).

## Capacity

None of the SRS's performance targets (NFR-1.x, NFR-2.x) has a benchmark in CI
yet, and none should be treated as met. Measured and recorded: forking a
workspace takes about 0.35 ms whether it holds 10 files or 1,000
(`go test ./internal/graph -bench ForkAttempt`).
