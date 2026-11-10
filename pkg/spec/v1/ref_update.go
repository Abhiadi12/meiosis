package v1

import (
	"regexp"
	"strings"
	"time"
)

var gitObjectID = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// ValidGitObjectID reports whether s is a full SHA-1 or SHA-256 Git object ID.
func ValidGitObjectID(s string) bool { return gitObjectID.MatchString(s) }

// RefUpdate records that a Git ref moved, and the world the new commit's tree
// hashes to (FR-2.2). It is the bridge between the two DAGs: the commit DAG Git
// tooling reads and the world hashes evidence is bound to. It is append-only and
// signed by the server that observed the push, which vouches for what the push
// did; the pusher is named, with the capability chain it presented.
type RefUpdate struct {
	ID        string `json:"id"`
	Repo      string `json:"repo"`
	Ref       string `json:"ref"`
	OldCommit string `json:"old_commit,omitempty"` // absent when the push created the ref
	NewCommit string `json:"new_commit"`

	// World is the hash of the tree at NewCommit, computed the same way as the
	// world of an attempt, so identical trees hash identically however they
	// arrived. BaseWorld is the hash of the tree at OldCommit, when there was one.
	World     WorldHash  `json:"world"`
	BaseWorld *WorldHash `json:"base_world,omitempty"`

	PushedBy string `json:"pushed_by"`
	// Token is the capability token, with its delegation chain, the push was
	// made under. Absent for a push accepted without authentication.
	Token *CapabilityToken `json:"token,omitempty"`

	// Intent is the intent the push is under. ImplicitIntent is true when none
	// was named and the server derived one with scope mode "warn" (IF-1).
	Intent         string `json:"intent"`
	ImplicitIntent bool   `json:"implicit_intent,omitempty"`
	// Attempt is an existing attempt whose world equals this push's, if any:
	// the push delivered the tree that attempt produced.
	Attempt string `json:"attempt,omitempty"`

	ChangedPaths    int              `json:"changed_paths"`
	ScopeViolations []ScopeViolation `json:"scope_violations,omitempty"`

	// SecretScan is the mode the push was scanned under ("off", "warn" or
	// "block"); SecretFindings are what it found, naming the place and the rule
	// but never the secret (NFR-4.4). SecretScanTruncated is true when the diff
	// was too large to be scanned whole.
	SecretScan          string          `json:"secret_scan,omitempty"`
	SecretFindings      []SecretFinding `json:"secret_findings,omitempty"`
	SecretScanTruncated bool            `json:"secret_scan_truncated,omitempty"`

	At       time.Time `json:"at"`
	SignedBy string    `json:"signed_by"`
	// Signature is by SignedBy over the canonical record.
	Signature string `json:"signature"`
}

// SecretFinding is one place a push scan found what looks like a credential.
type SecretFinding struct {
	Path       string `json:"path"`
	Line       int    `json:"line,omitempty"` // 0 when the finding is about the path itself
	Rule       string `json:"rule"`
	Confidence string `json:"confidence"` // "high" or "possible"
}

// Validate reports whether the record is well formed; it checks shape, not the signature.
func (r RefUpdate) Validate() error {
	if !validContentID(r.ID, "ref_") || strings.TrimSpace(r.Repo) == "" || !strings.HasPrefix(r.Ref, "refs/") ||
		!ValidGitObjectID(r.NewCommit) || (r.OldCommit != "" && !ValidGitObjectID(r.OldCommit)) ||
		r.World.Validate() != nil || !validPrincipalID(r.PushedBy) || !validContentID(r.Intent, "int_") ||
		r.ChangedPaths < 0 || r.At.IsZero() || !validPrincipalID(r.SignedBy) || strings.TrimSpace(r.Signature) == "" {
		return ErrInvalidRefUpdate
	}
	if r.BaseWorld != nil && r.BaseWorld.Validate() != nil {
		return ErrInvalidRefUpdate
	}
	if (r.OldCommit == "") != (r.BaseWorld == nil) {
		return ErrInvalidRefUpdate // a base world exists exactly when there was an old commit
	}
	if r.Attempt != "" && !validContentID(r.Attempt, "att_") {
		return ErrInvalidRefUpdate
	}
	if r.Token != nil && r.Token.Validate() != nil {
		return ErrInvalidRefUpdate
	}
	for _, v := range r.ScopeViolations {
		if strings.TrimSpace(v.Path) == "" {
			return ErrInvalidRefUpdate
		}
	}
	switch r.SecretScan {
	case "", "off", "warn", "block":
	default:
		return ErrInvalidRefUpdate
	}
	for _, f := range r.SecretFindings {
		if strings.TrimSpace(f.Path) == "" || strings.TrimSpace(f.Rule) == "" || f.Line < 0 || (f.Confidence != "high" && f.Confidence != "possible") {
			return ErrInvalidRefUpdate
		}
	}
	return nil
}
