package scope

import (
	"fmt"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

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
func (i *Intent) Evaluate(filePath string) (Decision, error) {
	if err := validatePath(filePath); err != nil {
		return Decision{}, err
	}

	for _, denyPattern := range i.Deny {
		match, err := doublestar.Match(denyPattern, filePath)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid deny pattern '%s': %w", denyPattern, err)
		}
		if match {
			return Decision{Reason: fmt.Sprintf("matches deny rule %q", denyPattern)}, nil
		}
	}

	if len(i.Allow) == 0 {
		return Decision{Reason: "the scope allows no paths"}, nil
	}
	for _, allowPattern := range i.Allow {
		match, err := doublestar.Match(allowPattern, filePath)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid allow pattern '%s': %w", allowPattern, err)
		}
		if match {
			return Decision{Allowed: true, Reason: fmt.Sprintf("matches allow rule %q", allowPattern)}, nil
		}
	}
	return Decision{Reason: fmt.Sprintf("matches no allow rule (allow: %s)", strings.Join(i.Allow, ", "))}, nil
}

// IsPathAllowed reports whether path is permitted; see Evaluate.
func (i *Intent) IsPathAllowed(filePath string) (bool, error) {
	d, err := i.Evaluate(filePath)
	return d.Allowed, err
}

func validatePath(filePath string) error {
	if filePath == "" || strings.HasPrefix(filePath, "/") || strings.Contains(filePath, "\\") {
		return fmt.Errorf("invalid file path %q: paths must be relative slash-separated paths", filePath)
	}
	clean := path.Clean(filePath)
	if clean != filePath || clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return fmt.Errorf("invalid file path %q: path traversal is not allowed", filePath)
	}
	return nil
}
