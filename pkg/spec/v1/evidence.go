package v1

import (
	"encoding/json"
	"strings"
	"time"
)

// EvidenceKind names the type of an Evidence record and selects its payload schema.
type EvidenceKind string

// The built-in evidence kinds. Custom kinds are prefixed "x-".
const (
	EvidenceKindTestRun        EvidenceKind = "test-run"
	EvidenceKindCoverage       EvidenceKind = "coverage"
	EvidenceKindTypeCheck      EvidenceKind = "type-check"
	EvidenceKindStaticAnalysis EvidenceKind = "static-analysis"
	EvidenceKindBenchmark      EvidenceKind = "benchmark"
	EvidenceKindMutation       EvidenceKind = "mutation"
	EvidenceKindSecurityScan   EvidenceKind = "security-scan"
	EvidenceKindReplayMatch    EvidenceKind = "replay-match"
	EvidenceKindHumanReview    EvidenceKind = "human-review"
)

// EvidenceOutcome is the result an Evidence record reports.
type EvidenceOutcome string

// The outcomes an Evidence record can report.
const (
	EvidenceOutcomePass         EvidenceOutcome = "pass"
	EvidenceOutcomeFail         EvidenceOutcome = "fail"
	EvidenceOutcomeInconclusive EvidenceOutcome = "inconclusive"
)

// Evidence is a signed claim about one world, produced by one principal. See spec/v1/evidence.md.
type Evidence struct {
	ID       string       `json:"id"`
	Attempt  string       `json:"attempt"`
	World    WorldHash    `json:"world"`
	Kind     EvidenceKind `json:"kind"`
	Producer string       `json:"producer"`
	// Independent is true when Producer differs from the attempt's author
	// (FR-4.4). It is computed by the server at submission, never supplied by
	// the caller, and omitted from the encoding when false.
	Independent bool `json:"independent,omitempty"`
	// Supersedes names an earlier evidence record this one corrects
	// (FR-4.12). The earlier record is never altered; it simply stops
	// counting.
	Supersedes string          `json:"supersedes,omitempty"`
	Outcome    EvidenceOutcome `json:"outcome"`
	Footprint  []string        `json:"footprint,omitempty"`
	Payload    json.RawMessage `json:"payload"`
	ExpiresAt  time.Time       `json:"expires_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	Signature  string          `json:"signature"`
}

// Validate reports whether the evidence is well formed; it checks shape, not signatures or the payload schema.
func (e Evidence) Validate() error {
	if strings.TrimSpace(e.ID) == "" || !validContentID(e.Attempt, "att_") || e.World.Validate() != nil || !validPrincipalID(e.Producer) || !validEvidenceKind(e.Kind) || !validEvidenceOutcome(e.Outcome) || len(e.Payload) == 0 || !json.Valid(e.Payload) || e.CreatedAt.IsZero() || strings.TrimSpace(e.Signature) == "" {
		return ErrInvalidEvidence
	}
	if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(e.CreatedAt) {
		return ErrInvalidEvidence
	}
	if e.Supersedes != "" && (strings.TrimSpace(e.Supersedes) == "" || e.Supersedes == e.ID) {
		return ErrInvalidEvidence
	}
	return nil
}

// CustomKindPrefix namespaces user-registered evidence kinds so they can never
// collide with a built-in kind added in a later version of the format.
const CustomKindPrefix = "x-"

// IsCustomEvidenceKind reports whether k is a well-formed custom kind: the
// "x-" prefix followed by lower-case letters, digits and hyphens, starting with
// a letter or digit, at most 64 characters in all.
func IsCustomEvidenceKind(k EvidenceKind) bool {
	name, ok := strings.CutPrefix(string(k), CustomKindPrefix)
	if !ok || name == "" || len(k) > 64 {
		return false
	}
	for i, r := range name {
		letter := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		if !letter && !digit && (r != '-' || i == 0 || i == len(name)-1) {
			return false
		}
	}
	return true
}

// IsBuiltinEvidenceKind reports whether k is one of the kinds the format defines.
func IsBuiltinEvidenceKind(k EvidenceKind) bool {
	return k == EvidenceKindTestRun || k == EvidenceKindCoverage || k == EvidenceKindTypeCheck || k == EvidenceKindStaticAnalysis || k == EvidenceKindBenchmark || k == EvidenceKindMutation || k == EvidenceKindSecurityScan || k == EvidenceKindReplayMatch || k == EvidenceKindHumanReview
}

func validEvidenceKind(k EvidenceKind) bool {
	return IsBuiltinEvidenceKind(k) || IsCustomEvidenceKind(k)
}

func validEvidenceOutcome(o EvidenceOutcome) bool {
	return o == EvidenceOutcomePass || o == EvidenceOutcomeFail || o == EvidenceOutcomeInconclusive
}

// EvidenceKindDef registers a custom evidence kind (FR-4.2) together with the
// JSON Schema its payloads must satisfy. Registrations are immutable: a changed
// schema is a new kind name (for example x-license-check-v2).
type EvidenceKindDef struct {
	Kind         EvidenceKind    `json:"kind"`
	Schema       json.RawMessage `json:"schema"`
	RegisteredBy string          `json:"registered_by"`
	RegisteredAt time.Time       `json:"registered_at"`
	Signature    string          `json:"signature"`
}

// Validate reports whether the kind definition is well formed.
func (d EvidenceKindDef) Validate() error {
	if !IsCustomEvidenceKind(d.Kind) || !validPrincipalID(d.RegisteredBy) || d.RegisteredAt.IsZero() || strings.TrimSpace(d.Signature) == "" {
		return ErrInvalidEvidence
	}
	var schema map[string]any
	if len(d.Schema) == 0 || json.Unmarshal(d.Schema, &schema) != nil || schema == nil {
		return ErrInvalidEvidence
	}
	return nil
}
