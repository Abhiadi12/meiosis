// Package storage defines the backend-neutral persistence contract used by
// Meiosis components.
package storage

import (
	"errors"
)

var (
	ErrNotFound    = errors.New("storage record not found")
	ErrInvalidKey  = errors.New("invalid storage key")
	ErrInvalidBlob = errors.New("invalid blob identifier")
)

// Kind identifies one of the immutable M0 record collections.
type Kind string

// BlobID is the lower-case hexadecimal BLAKE3-256 identifier of blob content.
type BlobID string

const (
	KindPrincipal   Kind = "principals"
	KindIntent      Kind = "intents"
	KindAttempt     Kind = "attempts"
	KindWorld       Kind = "worlds"
	KindEvidence    Kind = "evidence"
	KindAttestation Kind = "attestations"
	KindVerdict     Kind = "verdicts"
	KindRevocation  Kind = "revocations"

	// KindAttemptState holds the mutable current view of an attempt (world,
	// scope violations, status). The attempt itself, in KindAttempt, is
	// immutable; per SRS §4.4 mutable state lives in a separate *_state table.
	KindAttemptState Kind = "attempt_states"
	// KindIntentState holds the mutable lifecycle state of an intent (status,
	// supersession). The intent itself, in KindIntent, is immutable.
	KindIntentState Kind = "intent_states"
	// KindEvidenceKind holds registered custom evidence kinds and their payload
	// schemas. Registrations are immutable.
	KindEvidenceKind Kind = "evidence_kinds"
	// KindTokenSpend holds the running cost charged against each capability
	// token's spend ceiling. It is mutable bookkeeping, not evidence.
	KindTokenSpend Kind = "token_spend"
	// KindAuthority holds the append-only record of which capability chain
	// authorised each write.
	KindAuthority Kind = "authority_log"
	// KindRefUpdate holds the append-only record of every Git ref update and the
	// world hash it produced.
	KindRefUpdate Kind = "ref_updates"
	// KindOperation holds the append-only operation log of every workspace.
	KindOperation Kind = "operations"
	// KindIdempotency holds the result of each mutating call that carried an
	// idempotency key, so a retry gets the original answer instead of doing the
	// work twice.
	KindIdempotency Kind = "idempotency_keys"
	// KindWorkspace holds an attempt's uncommitted working set: mutable
	// scratch space, kept out of the append-only worlds table.
	KindWorkspace Kind = "workspaces"
)
