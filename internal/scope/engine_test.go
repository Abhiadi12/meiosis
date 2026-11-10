package scope

import (
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestIsPathAllowedMatchesNestedGlobs(t *testing.T) {
	e := New(specv1.Scope{Allow: []string{"internal/auth/**/*.go"}, Mode: specv1.ScopeModeEnforce})

	allowed, err := e.IsPathAllowed("internal/auth/oidc/handler.go")
	if err != nil {
		t.Fatalf("IsPathAllowed() error = %v", err)
	}
	if !allowed {
		t.Fatal("IsPathAllowed() = false, want true for a nested match")
	}
}

func TestIsPathAllowedDenyOverridesAllow(t *testing.T) {
	e := New(specv1.Scope{
		Allow: []string{"internal/auth/**"},
		Deny:  []string{"internal/auth/secrets/**"},
		Mode:  specv1.ScopeModeEnforce,
	})

	allowed, err := e.IsPathAllowed("internal/auth/secrets/keys.pem")
	if err != nil {
		t.Fatalf("IsPathAllowed() error = %v", err)
	}
	if allowed {
		t.Fatal("IsPathAllowed() = true, want false: deny should override an overlapping allow")
	}

	allowed, err = e.IsPathAllowed("internal/auth/handler.go")
	if err != nil {
		t.Fatalf("IsPathAllowed() error = %v", err)
	}
	if !allowed {
		t.Fatal("IsPathAllowed() = false, want true for a path outside the deny rule")
	}
}

func TestIsPathAllowedDefaultsToDenyForUnmatchedPath(t *testing.T) {
	e := New(specv1.Scope{Allow: []string{"internal/auth/**"}, Mode: specv1.ScopeModeEnforce})

	allowed, err := e.IsPathAllowed("internal/billing/invoice.go")
	if err != nil {
		t.Fatalf("IsPathAllowed() error = %v", err)
	}
	if allowed {
		t.Fatal("IsPathAllowed() = true, want false for a path matching no allow rule")
	}
}

func TestIsPathAllowedRejectsInvalidPattern(t *testing.T) {
	e := New(specv1.Scope{Allow: []string{"["}, Mode: specv1.ScopeModeEnforce})

	if _, err := e.IsPathAllowed("anything.go"); err == nil {
		t.Fatal("IsPathAllowed() expected error for malformed glob pattern")
	}
}

func TestEngineRejectsUnsafePaths(t *testing.T) {
	e := New(specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce})
	for _, path := range []string{"", "/etc/passwd", "../secret", "pkg/../secret"} {
		if allowed, err := e.IsPathAllowed(path); err == nil || allowed {
			t.Errorf("IsPathAllowed(%q) = %v, %v; want false and an error", path, allowed, err)
		}
	}
}
