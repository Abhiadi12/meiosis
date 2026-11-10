package identity

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// globCovers reports whether every path matched by inner is also matched by
// outer. It is conservative: it answers true only when it can show coverage,
// and false when unsure, so a delegation is refused rather than wrongly
// allowed. Patterns using braces or escapes are covered only by an identical
// pattern.
func globCovers(outer, inner string) bool {
	if outer == inner {
		return true
	}
	if strings.ContainsAny(outer, "{\\") || strings.ContainsAny(inner, "{\\") {
		return false
	}
	if outer == "" || inner == "" || strings.HasPrefix(outer, "/") || strings.HasPrefix(inner, "/") {
		return false
	}
	outerSegs := strings.Split(outer, "/")
	// doublestar does not treat repeated "**" segments uniformly (for example
	// "a/**/**" does not match "a" although "a/**" does), so such an outer pattern
	// may match less than this analysis assumes. Only an identical pattern is
	// accepted as covered by it. (An inner pattern that over-approximates is
	// harmless: coverage of a larger set implies coverage of the real one.)
	for i := 1; i < len(outerSegs); i++ {
		if outerSegs[i] == "**" && outerSegs[i-1] == "**" {
			return false
		}
	}
	return segsCover(outerSegs, strings.Split(inner, "/"))
}

func segsCover(outer, inner []string) bool {
	if len(inner) == 0 {
		// Leftover outer segments could only be a trailing "**", which is not
		// credited with matching nothing (see below).
		return len(outer) == 0
	}
	if len(outer) == 0 {
		return false
	}
	if outer[0] == "**" {
		if len(outer) == 1 {
			// A trailing ** is only credited with at least one segment (see
			// above), so it covers the rest of inner only if inner is guaranteed
			// to supply one: it needs a fixed segment, not just more "**".
			for _, seg := range inner {
				if seg != "**" {
					return true
				}
			}
			return false
		}
		// A ** that is not last absorbs any number of leading segments of inner,
		// including none.
		for k := 0; k <= len(inner); k++ {
			if segsCover(outer[1:], inner[k:]) {
				return true
			}
		}
		return false
	}
	if inner[0] == "**" {
		return false // inner may span many segments; one fixed segment cannot cover that
	}
	if !segCovers(outer[0], inner[0]) {
		return false
	}
	return segsCover(outer[1:], inner[1:])
}

func segCovers(outer, inner string) bool {
	if outer == inner || outer == "*" {
		return true
	}
	if strings.ContainsAny(inner, "*?[") {
		return false // both are patterns and not identical: cannot show coverage
	}
	ok, err := doublestar.Match(outer, inner)
	return err == nil && ok
}

// scopeNarrower reports why child is not a subset of parent, or nil. The child
// must allow only paths the parent allows, must deny everything the parent
// denies, and may not relax a scope mode of "enforce".
//
// Soundness: a path the child allows matches some child allow pattern P, which
// is covered by a parent allow pattern, and no child deny pattern. If it
// matched a parent deny pattern D, some child deny pattern would cover D and so
// match it too, a contradiction. So the path is allowed by the parent.
func scopeNarrower(parent, child specv1.Scope) error {
	for _, p := range child.Allow {
		covered := false
		for _, q := range parent.Allow {
			if globCovers(q, p) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("%w: allow %q is not within the parent's allow set %v", ErrWidening, p, parent.Allow)
		}
	}
	for _, d := range parent.Deny {
		covered := false
		for _, e := range child.Deny {
			if globCovers(e, d) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("%w: the parent denies %q and the delegated scope does not", ErrWidening, d)
		}
	}
	if parent.Mode == specv1.ScopeModeEnforce && child.Mode != specv1.ScopeModeEnforce {
		return fmt.Errorf("%w: the parent's scope mode is enforce", ErrWidening)
	}
	return nil
}

func unrestricted(ops []string) bool {
	if len(ops) == 0 {
		return true
	}
	for _, o := range ops {
		if o == specv1.CapabilityOperationAll {
			return true
		}
	}
	return false
}

// operationsNarrower reports why child's operations are not within parent's.
func operationsNarrower(parent, child []string) error {
	if unrestricted(parent) {
		return nil
	}
	if unrestricted(child) {
		return fmt.Errorf("%w: the parent is limited to %v", ErrWidening, parent)
	}
	allowed := map[string]bool{}
	for _, o := range parent {
		allowed[o] = true
	}
	for _, o := range child {
		if !allowed[o] {
			return fmt.Errorf("%w: operation %q is not among the parent's %v", ErrWidening, o, parent)
		}
	}
	return nil
}

// narrower reports why child holds more authority than parent, or nil. It
// checks every axis of authority a token carries (FR-1.4): intent, path scope,
// operations, spend ceiling and lifetime.
func narrower(parent, child specv1.CapabilityToken) error {
	if parent.Intent != specv1.CapabilityTokenAnyIntent && child.Intent != parent.Intent {
		return fmt.Errorf("%w: the parent is bound to %s", ErrWidening, parent.Intent)
	}
	if err := scopeNarrower(parent.Scope, child.Scope); err != nil {
		return err
	}
	if err := operationsNarrower(parent.Operations, child.Operations); err != nil {
		return err
	}
	if parent.SpendCeilingMicros != nil {
		switch {
		case child.SpendCeilingMicros == nil:
			return fmt.Errorf("%w: the parent has a spend ceiling of %d", ErrWidening, *parent.SpendCeilingMicros)
		case *child.SpendCeilingMicros > *parent.SpendCeilingMicros:
			return fmt.Errorf("%w: spend ceiling %d exceeds the parent's %d", ErrWidening, *child.SpendCeilingMicros, *parent.SpendCeilingMicros)
		}
	}
	if child.ExpiresAt.After(parent.ExpiresAt) {
		return fmt.Errorf("%w: the token would outlive its parent", ErrWidening)
	}
	if child.IssuedAt.Before(parent.IssuedAt) {
		return fmt.Errorf("%w: the token is dated before its parent", ErrWidening)
	}
	return nil
}
