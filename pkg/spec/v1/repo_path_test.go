package v1

import "testing"

func TestValidRepoPath(t *testing.T) {
	for p, want := range map[string]bool{
		"a": true, "a/b.go": true, "a/b/c": true, ".hidden/x": true,
		"": false, "/abs": false, "a/../b": false, "../x": false, "..": false, ".": false,
		"a//b": false, "a/": false, "./a": false, `a\b`: false,
	} {
		if got := ValidRepoPath(p); got != want {
			t.Errorf("ValidRepoPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestWorldHashShort(t *testing.T) {
	var h WorldHash
	h[0] = 0xab
	if got := h.Short(); got != "ab0000000000" {
		t.Fatalf("Short = %q", got)
	}
}
