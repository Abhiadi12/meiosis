package v1

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseFootprint(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil means whole world", nil, nil},
		{"empty means whole world", []string{}, nil},
		{"exact path", []string{"internal/auth/token.go"}, []string{"internal/auth/token.go"}},
		{"glob", []string{"internal/auth/**"}, []string{"internal/auth/**"}},
		{"single-star glob", []string{"cmd/*/main.go"}, []string{"cmd/*/main.go"}},
		{"sorted", []string{"b.go", "a.go"}, []string{"a.go", "b.go"}},
		{"duplicates removed", []string{"a.go", "b.go", "a.go"}, []string{"a.go", "b.go"}},
		{"path covered by glob dropped", []string{"a/b.go", "a/**"}, []string{"a/**"}},
		{"path not covered by glob kept", []string{"a/**", "c/d.go"}, []string{"a/**", "c/d.go"}},
		{"overlapping globs both kept", []string{"a/**", "a/b/**"}, []string{"a/**", "a/b/**"}},
		{"whole-world glob", []string{"**", "x.go"}, []string{"**"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFootprint(tt.in)
			if err != nil {
				t.Fatalf("ParseFootprint(%q) error = %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseFootprint(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseFootprintRejects(t *testing.T) {
	tests := []struct {
		name   string
		in     []string
		reason string
	}{
		{"empty entry", []string{""}, "clean, relative"},
		{"absolute path", []string{"/etc/passwd"}, "clean, relative"},
		{"parent traversal", []string{"internal/auth/../billing/x.go"}, "clean, relative"},
		{"leading dot segment", []string{"./internal/auth"}, "clean, relative"},
		{"backslash", []string{`internal\auth`}, "clean, relative"},
		{"trailing slash", []string{"internal/auth/"}, "clean, relative"},
		{"unclosed bracket", []string{"internal/[bad"}, "glob"},
		{"unclosed brace", []string{"internal/{a,b"}, "glob"},
		{"symbol", []string{"sym:internal/auth.Verify"}, "symbol"},
		{"one bad entry among good ones", []string{"a.go", "/abs"}, "entry 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFootprint(tt.in)
			if !errors.Is(err, ErrInvalidFootprint) {
				t.Fatalf("ParseFootprint(%q) = %q, %v; want ErrInvalidFootprint", tt.in, got, err)
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Fatalf("ParseFootprint(%q) error = %q, want it to mention %q", tt.in, err, tt.reason)
			}
		})
	}
}

func TestParseFootprintCap(t *testing.T) {
	entries := make([]string, MaxFootprintEntries)
	for i := range entries {
		entries[i] = fmt.Sprintf("f%d.go", i)
	}
	if _, err := ParseFootprint(entries); err != nil {
		t.Fatalf("ParseFootprint(%d entries) error = %v, want nil", len(entries), err)
	}
	entries = append(entries, "one-more.go")
	if _, err := ParseFootprint(entries); !errors.Is(err, ErrInvalidFootprint) {
		t.Fatalf("ParseFootprint(%d entries) error = %v, want ErrInvalidFootprint", len(entries), err)
	}
}

// Normalising must not depend on input order, or the same footprint could sign
// to different bytes.
func TestParseFootprintOrderIndependent(t *testing.T) {
	a, errA := ParseFootprint([]string{"z.go", "a/**", "a/x.go", "m.go"})
	b, errB := ParseFootprint([]string{"m.go", "a/x.go", "z.go", "a/**", "m.go"})
	if errA != nil || errB != nil {
		t.Fatalf("errors: %v, %v", errA, errB)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("same footprint normalised differently: %q vs %q", a, b)
	}
}

func TestParseFootprintDoesNotModifyInput(t *testing.T) {
	in := []string{"b.go", "a.go"}
	if _, err := ParseFootprint(in); err != nil {
		t.Fatal(err)
	}
	if in[0] != "b.go" || in[1] != "a.go" {
		t.Fatalf("input changed to %q", in)
	}
}
