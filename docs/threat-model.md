# Threat model

Required by NFR-4.6 and to be reviewed at each minor release. This describes
meiosis as it is today (M1), including what it does **not** defend against.
Where a claim is backed by a test, the test is named.

## What is being protected

- **The integrity of the record**: that an intent, an attempt, a piece of evidence
  or a ref update says what actually happened, and was made by who it says.
- **The boundary an intent draws**: that work done under an intent stays inside
  the paths it names.
- **The independence of evidence**: that an author cannot vouch for its own work.
- **Credentials**: private keys, capability tokens, and whatever an agent might
  paste into code.
- **Availability** of a single-node server to the people using it.

## Who the adversary is (SRS §7.4)

**Primary: a compromised or misbehaving agent that holds valid credentials.**
Not an outsider breaking in: an agent that was given a token and then goes
beyond it, whether through a bug, a prompt injection or a malicious sub-agent.

**Secondary: an insider** who tries to back-date, forge or launder evidence.

**Out of scope for this release:** a compromised meiosis server or its host, and
anyone with write access to the database file or the private keys, who can do
anything the server can.

## Trust boundaries

```
 human (CLI) ── human key ───────────────┐
 agent ──(MCP stdio/socket/HTTP, REST)── meiosisd / mei serve ── SQLite ── git repos
 git client ──(smart HTTP, bearer token)─┘            ▲
                                              receive hooks (same user)
```

- The **server and the keys on its disk are trusted.** Everything that arrives
  over a socket, from a report file, from a git push or from an agent is not.
- **Tokens are bearer credentials.** Whoever holds one can use it until it
  expires or is revoked, as the principal it names.

## Threats, defences and what is left

| # | Threat | Defence | Test | Left over |
|---|---|---|---|---|
| T1 | Agent writes outside its intent's scope | Scope checked at write time, again at commit, and at push; `enforce` rejects, `warn` records. Paths are validated: absolute, `..`, backslashes refused | `TestAdversarial_AgentWritesOutsideDeclaredScope`, `TestEnforcedIntentScopeRejects…` | Scope is by path glob only. It cannot say "this function", and a path inside scope can still hold harmful content (M3 adds symbol analysis) |
| T2 | Agent widens its own authority | Tokens are signed by the issuer, not the holder. A delegated token may only narrow its parent on every axis, checked at issuance **and at every verification**; the glob-subset check is conservative and property-tested | `TestPropertyAcceptedDelegationNeverWidensScope`, `TestVerifyRejectsHandSignedWideningAndForgedChains` | Delegation depth is capped at 8; a leaked holder key lets the thief delegate anything within that token |
| T3 | Forged or edited token | Ed25519 signature over the canonical form, including the embedded parent chain; the chain must end at a `human:` principal and verify under the trusted issuer key | `TestAdversarial_ForgedAndStolenCredentials` | No audience binding beyond the principal name; a token stolen from a log is usable |
| T4 | Stolen or leaked token | Short default lifetime (1 h); revocation takes effect on the next call, and revoking a token revokes everything delegated from it | `TestRevokedTokenIsRefusedAcrossStoreInstances`, `TestRevokingAnAncestorRevokesEveryDelegation` | No refresh or rotation protocol; tokens travel in HTTP headers, so **TLS is the operator's job** when not on loopback |
| T5 | Agent grades its own homework | Evidence records the producer; `independent` is computed, not supplied; a client cannot name another producer; only the original producer may supersede a record | `TestAdversarial_AgentSubmitsEvidenceForAWorldItAuthored`, `TestOnlyTheProducerMaySupersedeItsEvidence` | Nothing *acts* on independence until the policy gate (M2). Two principals controlled by one party are indistinguishable |
| T6 | Stale proof passes for fresh | Evidence is bound to a world hash; evidence for a superseded world is accepted but never counted | `TestAdversarial_EvidenceForASupersededWorld` | Only whole-world binding; footprint-based carry-over is M2 |
| T7 | Back-dated evidence | The server assigns every timestamp; a client-supplied `created_at` is ignored | `TestAdversarial_ABackdatedTimestampIsNotAccepted` | Records are append-only and signed but not chained (no Merkle log until M3): someone with the database can reorder them |
| T8 | Overwriting history | Intents, attempts, evidence, attestations, operations and ref updates are immutable once stored; changing one is refused; deleting refs and force-pushing are refused | `TestEvidenceAndIntentCannotBeOverwritten`, `TestDeletingARefAndRewritingHistoryAreRefused` | The database file itself is writable by whoever owns it |
| T9 | Malicious report fed to an adapter | Size limit (32 MiB), XML nesting limit, no external entities, payload size caps; adapters are fuzzed | `FuzzParse` (found and fixed a real bug), `TestDeeplyNestedXMLIsRejectedNotCrashed` | The fuzzing is time-boxed, not exhaustive |
| T10 | Credentials pushed in code | Pushes are scanned for recognisable credentials and credential files; `secrets: block` refuses high-confidence matches; findings name the place and rule, never the secret | `TestBlockModeRefusesAPushWith…`, `TestFindingsNameTheRuleNeverTheSecret` | A **tripwire, not a guarantee**: an unrecognised secret passes. Default mode is `warn`. History already pushed is not rescanned. Anything that reached a remote must be treated as leaked |
| T11 | Prompt text leaks secrets | Only the BLAKE3 digest of a prompt is stored (NFR-4.2) | `TestCommitRecordsSignedProvenanceAndNeverStoresPrompt` | Anything an agent puts in a *file* or in evidence payloads is stored |
| T12 | Unauthenticated access | Enforcement is on by default and cannot be disabled in a `strict` repository; `meiosisd` and `mei serve` refuse to start without an issuer key | `TestStrictRepositoryForbidsRunningWithoutEnforcement`, `TestPushNeedsACapabilityToken` | `--allow-unauthenticated` exists for non-strict repositories and is loud about it |
| T13 | Cross-site or DNS-rebinding attack on the local server | `/mcp` and `/api/v1` refuse a request that names a different `Origin`; the default bind is loopback; metrics are loopback-only | `TestMCPEndpoint…`, `TestAPIStatusCodes…`, `TestHandlerServesLoopbackOnly` | Not a defence against a hostile process on the same host |
| T14 | Replaying a recorded response | An idempotent replay still requires a currently valid token; keys are per principal and tool | `TestAReplayStillNeedsAValidToken` | |
| T15 | Outbound exfiltration | The shipped code contains no outbound networking; a full session's sockets are loopback only; no telemetry or licence check (NFR-4.5) | `TestNoOutboundNetworkCodeInTheShippedPackages`, `TestAdversarial_ServerRunsFullyWithNoNetworkAccess` | A hermetic network-namespace test is not done |

## Known weaknesses, stated plainly

1. **Server-attested, not self-signed, git records.** A pusher presents a bearer
   token, not a key, so a ref update is signed by the server. It proves the server
   saw the push, not that the pusher signed it.
2. **Records are written just after the write.** An authority record or ref
   update is appended after the change it describes; if that append fails the
   change stands and the caller is told. There is no cross-record transaction.
3. **Stored objects are not re-verified on read.** Signatures are checked when a
   token is used, not when a stored object is loaded, so an object altered
   directly in the database is not detected (M2 adds a principal registry and
   verify-on-read).
4. **Git commit signatures are not checked.** `strict` means a valid token is
   required, not a signed commit.
5. **Hooks run as the server's user.** The receive hooks are the server's own
   binary, but anyone who can write the repository's `hooks/` directory can
   replace them.
6. **No rate limiting or quotas** beyond the spend ceiling on commits. A client
   with a valid token can create records until the disk fills.
7. **Keys at rest** are files with mode 0600 and are not encrypted.
8. **The `/mcp` endpoint acts as one principal** (the repository's agent): any
   holder of that principal's token is that agent.

## Reviewing this document

Review at every minor release. A change that adds an input (a new adapter, a new
transport, a new way to obtain a token) needs a row here before it ships.
