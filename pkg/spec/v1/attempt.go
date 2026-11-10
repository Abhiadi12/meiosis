package v1

import (
	"strings"
	"time"
)

// AttemptStatus is the lifecycle state of an Attempt.
type AttemptStatus string

// The statuses an Attempt can have.
const (
	AttemptStatusOpen      AttemptStatus = "open"
	AttemptStatusMerged    AttemptStatus = "merged"
	AttemptStatusAbandoned AttemptStatus = "abandoned"
)

// ScopeViolation records one path an attempt changed outside its intent's scope (warn mode).
type ScopeViolation struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

// Attempt is one principal's implementation of an Intent, identified by the world it produced. See spec/v1/attempt.md.
type Attempt struct {
	ID        string    `json:"id"`
	Intent    string    `json:"intent"`
	Author    string    `json:"author"`
	World     WorldHash `json:"world"`
	BaseWorld WorldHash `json:"base_world"`
	GitCommit string    `json:"git_commit,omitempty"`
	// ForkedFrom names the attempt whose workspace this one was forked from
	// (FR-2.3). It is set at creation and never changes.
	ForkedFrom      string           `json:"forked_from,omitempty"`
	ScopeViolations []ScopeViolation `json:"scope_violations,omitempty"`
	Status          AttemptStatus    `json:"status"`
	CreatedAt       time.Time        `json:"created_at"`
	Signature       string           `json:"signature"`
}

// Validate reports whether the attempt is well formed; it checks shape, not signatures.
func (a Attempt) Validate() error {
	if !validContentID(a.ID, "att_") || !validContentID(a.Intent, "int_") || !validPrincipalID(a.Author) || a.World.Validate() != nil || a.BaseWorld.Validate() != nil || a.CreatedAt.IsZero() || strings.TrimSpace(a.Signature) == "" {
		return ErrInvalidAttempt
	}
	if a.Status != AttemptStatusOpen && a.Status != AttemptStatusMerged && a.Status != AttemptStatusAbandoned {
		return ErrInvalidAttempt
	}
	if a.ForkedFrom != "" && (!validContentID(a.ForkedFrom, "att_") || a.ForkedFrom == a.ID) {
		return ErrInvalidAttempt
	}
	for _, v := range a.ScopeViolations {
		if strings.TrimSpace(v.Path) == "" {
			return ErrInvalidAttempt
		}
	}
	return nil
}
