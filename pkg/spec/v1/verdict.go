package v1

import (
	"encoding/json"
	"strings"
	"time"
)

// VerdictDecision is the outcome of a policy evaluation.
type VerdictDecision string

// The decisions a Verdict can record.
const (
	VerdictDecisionMerge    VerdictDecision = "merge"
	VerdictDecisionReject   VerdictDecision = "reject"
	VerdictDecisionEscalate VerdictDecision = "escalate"
)

// Risk is the assessed risk of merging a change.
type Risk struct {
	BlastRadius     int      `json:"blast_radius"`
	SensitivePaths  []string `json:"sensitive_paths"`
	IncidentDensity float64  `json:"incident_density"`
}

// Verdict is a signed decision about whether an attempt may merge. See spec/v1/verdict.md.
type Verdict struct {
	Attempt    string          `json:"attempt"`
	Decision   VerdictDecision `json:"decision"`
	DecidedBy  string          `json:"decided_by"`
	PolicyRef  string          `json:"policy_ref"`
	PolicyIn   json.RawMessage `json:"policy_in"`
	Risk       Risk            `json:"risk"`
	Confidence *float64        `json:"confidence,omitempty"`
	Rationale  string          `json:"rationale"`
	DecidedAt  time.Time       `json:"decided_at"`
	Signature  string          `json:"signature"`
}

// Validate reports whether the verdict is well formed; it checks shape, not signatures.
func (v Verdict) Validate() error {
	if !validContentID(v.Attempt, "att_") || !validPrincipalID(v.DecidedBy) || strings.TrimSpace(v.PolicyRef) == "" || len(v.PolicyIn) == 0 || !json.Valid(v.PolicyIn) || strings.TrimSpace(v.Rationale) == "" || v.DecidedAt.IsZero() || strings.TrimSpace(v.Signature) == "" {
		return ErrInvalidVerdict
	}
	if v.Decision != VerdictDecisionMerge && v.Decision != VerdictDecisionReject && v.Decision != VerdictDecisionEscalate {
		return ErrInvalidVerdict
	}
	if v.Risk.BlastRadius < 0 || v.Risk.IncidentDensity < 0 || v.Risk.IncidentDensity > 1 {
		return ErrInvalidVerdict
	}
	if v.Confidence != nil && (*v.Confidence < 0 || *v.Confidence > 1) {
		return ErrInvalidVerdict
	}
	return nil
}
