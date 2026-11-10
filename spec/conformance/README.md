# `spec/v1` Conformance Fixtures

This directory contains language-agnostic JSON fixtures for the `spec/v1`
format. Each core type has `valid/` and `invalid/` cases:

```text
spec/conformance/<type>/valid/*.json
spec/conformance/<type>/invalid/*.json
```

Valid fixtures must be accepted by an implementation. Invalid fixtures must be
rejected by object validation or JSON decoding. Fixture files contain the
wire-format object directly; they do not contain test-runner metadata.

The fixtures cover required fields, optional fields, constrained values, field
formats, nested objects, and representative JSON payloads. Relationship rules
that require repository state, such as dependency cycle detection, signature
verification, scope diff evaluation, and evidence freshness, are documented in
the relevant specification and require integration-level tests.

The Go adapter test in `conformance_test.go` exercises these fixtures against
the public `github.com/mindfire-test/meiosis/pkg/spec/v1` package. Other
implementations can consume the same JSON files without depending on Go or
Meiosis internals.

## Known-answer vectors

`vectors/` holds exact expected outputs (SRS §4.3, §11.4), not just accept/reject cases:

- `canonical.json`: RFC 8785 inputs and their canonical bytes.
- `signatures.json`: Ed25519 signatures from the fixed seed `00 01 … 1f`; Ed25519 is deterministic, so signing must reproduce them exactly.
- `content-ids.json`: object templates, canonical form and resulting `int_` / `evd_` IDs.
- `world-hashes.json`: file sets and their world hashes.

`verify_vectors.py` checks the same files with no Go code and no dependency on this implementation (`python3 verify_vectors.py`); a second implementation should pass both.
