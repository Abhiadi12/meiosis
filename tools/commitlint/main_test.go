package main

import (
	"strings"
	"testing"
)

func TestLint(t *testing.T) {
	long := strings.Repeat("x", 101)
	for _, c := range []struct {
		name, msg string
		ok        bool
	}{
		{"plain", "feat(api): add the endpoint", true},
		{"breaking bang", "feat(api)!: drop v0", true},
		{"body", "fix(cli): handle empty input\n\nlonger explanation\nover lines", true},
		{"trailers", "fix(cli): x\n\nSigned-off-by: A <a@b.c>\nCo-Authored-By: B <b@c.d>", true},
		{"merge", "Merge pull request #1 from a/b", true},
		{"git revert", "Revert \"feat(x): y\"", true},
		{"no scope", "feat: add thing", true},
		{"no scope breaking bang", "feat!: drop v0", true},
		{"bad type", "feature(api): add thing", false},
		{"upper subject", "feat(api): Add thing", false},
		{"full stop", "feat(api): add thing.", false},
		{"empty", "", false},
		{"no blank line", "feat(api): add\nbody", false},
		{"long header", "feat(api): " + long, false},
		{"long body", "feat(api): add\n\n" + strings.Repeat("y", 201), false},
		{"long url ok", "feat(api): add\n\nsee https://example.com/" + strings.Repeat("y", 250), true},
		{"empty scope", "feat(): add thing", false},
		{"scope space", "feat(a b): add", false},
	} {
		if got := len(Lint(c.msg)) == 0; got != c.ok {
			t.Errorf("%s: acceptable=%v, want %v (%v)", c.name, got, c.ok, Lint(c.msg))
		}
	}
}
