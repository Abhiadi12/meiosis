// Package scope evaluates a repo-relative path against an Intent's declared
// Allow/Deny glob rules (FR-3.3, FR-3.4, spec/v1.Scope). There is one
// implementation of the rules: Engine.
package scope

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// Engine evaluates paths against one spec/v1 Scope. Allow and Deny use
// doublestar glob syntax (for example pkg/auth/**); Deny always takes
// precedence over Allow.
type Engine struct {
	allow, deny []string
}

// New returns an Engine bound to the given scope.
func New(scope specv1.Scope) Engine {
	return Engine{allow: scope.Allow, deny: scope.Deny}
}

// Decision is the outcome of evaluating one path against a scope, with the
// rule that produced it so a rejection can be explained to a human or agent.
type Decision struct {
	Allowed bool
	// Reason is a legible explanation, e.g. `matches deny rule "src/secret/**"`
	// or `matches no allow rule (allow: src/**)`.
	Reason string
}

// Evaluate decides whether filePath is permitted. A path is allowed if it
// matches at least one Allow rule and no Deny rule; Deny takes precedence and
// an empty Allow list denies everything. An unsafe path (absolute, "..",
// backslashes, non-canonical) is an error rather than a quiet denial.
func (e Engine) Evaluate(filePath string) (Decision, error) {
	if err := validatePath(filePath); err != nil {
		return Decision{}, err
	}

	for _, denyPattern := range e.deny {
		match, err := doublestar.Match(denyPattern, filePath)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid deny pattern '%s': %w", denyPattern, err)
		}
		if match {
			return Decision{Reason: fmt.Sprintf("matches deny rule %q", denyPattern)}, nil
		}
	}

	if len(e.allow) == 0 {
		return Decision{Reason: "the scope allows no paths"}, nil
	}
	for _, allowPattern := range e.allow {
		match, err := doublestar.Match(allowPattern, filePath)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid allow pattern '%s': %w", allowPattern, err)
		}
		if match {
			return Decision{Allowed: true, Reason: fmt.Sprintf("matches allow rule %q", allowPattern)}, nil
		}
	}
	return Decision{Reason: fmt.Sprintf("matches no allow rule (allow: %s)", strings.Join(e.allow, ", "))}, nil
}

// IsPathAllowed reports whether path is permitted; see Evaluate.
func (e Engine) IsPathAllowed(filePath string) (bool, error) {
	d, err := e.Evaluate(filePath)
	return d.Allowed, err
}

func validatePath(filePath string) error {
	if !specv1.ValidRepoPath(filePath) {
		return fmt.Errorf("invalid file path %q: paths must be clean, relative, slash-separated and stay inside the repository", filePath)
	}
	return nil
}
