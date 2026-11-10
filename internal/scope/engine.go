// Package scope evaluates a repo-relative path against an Intent's declared
// Allow/Deny glob rules (FR-3.3, FR-3.4, spec/v1.Scope). There is one
// implementation of the rules, in scope.go; Engine is the adapter that binds it
// to a spec/v1 Scope.
package scope

import (
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// Engine evaluates paths against one Intent's Scope.
type Engine struct {
	rules Intent
}

// New returns an Engine bound to the given scope.
func New(scope specv1.Scope) Engine {
	return Engine{rules: Intent{Allow: scope.Allow, Deny: scope.Deny}}
}

// IsPathAllowed reports whether path is permitted by the engine's scope. Deny
// rules take precedence over Allow rules, a path matching no Allow rule is
// rejected (there is no implicit allow), and an unsafe path (absolute, "..",
// backslashes, non-canonical) is an error rather than a quiet "no".
func (e Engine) IsPathAllowed(path string) (bool, error) {
	return e.rules.IsPathAllowed(path)
}

// Evaluate is IsPathAllowed with the reason for the decision.
func (e Engine) Evaluate(path string) (Decision, error) {
	return e.rules.Evaluate(path)
}
