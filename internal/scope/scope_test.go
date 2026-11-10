package scope

import (
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestIsPathAllowed(t *testing.T) {
	tests := []struct {
		name    string
		intent  specv1.Scope
		path    string
		want    bool
		wantErr bool
	}{
		{
			name: "allowed path within glob",
			intent: specv1.Scope{
				Allow: []string{"pkg/auth/**"},
			},
			path: "pkg/auth/token.go",
			want: true,
		},
		{
			name: "allowed path deep within glob",
			intent: specv1.Scope{
				Allow: []string{"pkg/auth/**"},
			},
			path: "pkg/auth/middleware/session.go",
			want: true,
		},
		{
			name: "denied path by explicit deny rule",
			intent: specv1.Scope{
				Allow: []string{"pkg/auth/**"},
				Deny:  []string{"pkg/billing/**"},
			},
			path: "pkg/billing/invoice.go",
			want: false,
		},
		{
			name: "deny takes precedence over allow",
			intent: specv1.Scope{
				Allow: []string{"pkg/auth/**"},
				Deny:  []string{"pkg/auth/secrets.go"},
			},
			path: "pkg/auth/secrets.go",
			want: false,
		},
		{
			name: "path not in allow list defaults to false",
			intent: specv1.Scope{
				Allow: []string{"pkg/auth/**"},
			},
			path: "pkg/user/user.go",
			want: false,
		},
		{
			name:   "empty intent denies all",
			intent: specv1.Scope{},
			path:   "README.md",
			want:   false,
		},
		{
			name: "invalid allow pattern returns error",
			intent: specv1.Scope{
				Allow: []string{"["}, // malformed doublestar glob
			},
			path:    "test.go",
			wantErr: true,
		},
		{
			name: "invalid deny pattern returns error",
			intent: specv1.Scope{
				Allow: []string{"**/*.go"},
				Deny:  []string{"["}, // malformed doublestar glob
			},
			path:    "test.go",
			wantErr: true,
		},
		{
			name: "multiple allow rules",
			intent: specv1.Scope{
				Allow: []string{"pkg/auth/**", "cmd/mei/**"},
			},
			path: "cmd/mei/main.go",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.intent).IsPathAllowed(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsPathAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsPathAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPathAllowedRejectsUnsafePaths(t *testing.T) {
	intent := New(specv1.Scope{Allow: []string{"**"}})
	for _, path := range []string{"", "/etc/passwd", "../secret", "pkg/../secret", `pkg\\secret.go`} {
		t.Run(path, func(t *testing.T) {
			if allowed, err := intent.IsPathAllowed(path); err == nil || allowed {
				t.Fatalf("IsPathAllowed(%q) = %v, %v; want false and an error", path, allowed, err)
			}
		})
	}
}
