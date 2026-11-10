package textdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnified(t *testing.T) {
	cases := []struct {
		name          string
		before, after string
		want          string
	}{
		{"identical", "a\nb\n", "a\nb\n", ""},
		{"added line", "a\nc\n", "a\nb\nc\n", "--- a/f\n+++ b/f\n@@ -1,2 +1,3 @@\n a\n+b\n c\n"},
		{"removed line", "a\nb\nc\n", "a\nc\n", "--- a/f\n+++ b/f\n@@ -1,3 +1,2 @@\n a\n-b\n c\n"},
		{"changed line", "a\nb\nc\n", "a\nB\nc\n", "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"},
		{"from empty", "", "x\ny\n", "--- a/f\n+++ b/f\n@@ -0,0 +1,2 @@\n+x\n+y\n"},
		{"to empty", "x\ny\n", "", "--- a/f\n+++ b/f\n@@ -1,2 +0,0 @@\n-x\n-y\n"},
		{"no trailing newline", "a\nb", "a\nb\n", "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Unified("f", []byte(c.before), []byte(c.after), 3); got != c.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, c.want)
			}
		})
	}
}

func TestSeparateChangesGetSeparateHunksWhenFarApart(t *testing.T) {
	var before, after []string
	for i := 0; i < 40; i++ {
		before = append(before, "line"+string(rune('a'+i%26)))
	}
	after = append([]string(nil), before...)
	after[2], after[35] = "CHANGED-EARLY", "CHANGED-LATE"
	got := Unified("f", []byte(strings.Join(before, "\n")+"\n"), []byte(strings.Join(after, "\n")+"\n"), 2)
	if n := strings.Count(got, "@@ -"); n != 2 {
		t.Fatalf("hunks = %d, want 2:\n%s", n, got)
	}
}

func TestBinaryAndHugeInputsGetANoteNotADiff(t *testing.T) {
	if got := Unified("b", []byte("a\x00b"), []byte("a\x00c"), 3); !strings.Contains(got, "Binary files") {
		t.Fatalf("binary: %q", got)
	}
	big := strings.Repeat("x\n", MaxBytes)
	if got := Unified("big", []byte(big), []byte(big+"y\n"), 3); !strings.Contains(got, "too large") {
		t.Fatalf("huge: %q", got[:min(80, len(got))])
	}
	var a, b strings.Builder
	for i := 0; i < MaxMiddleLines+10; i++ {
		a.WriteString("a" + strings.Repeat("x", i%7) + "\n")
		b.WriteString("b" + strings.Repeat("y", i%5) + "\n")
	}
	if got := Unified("many", []byte(a.String()), []byte(b.String()), 3); !strings.Contains(got, "changed too much") {
		t.Fatalf("wholesale change: %q", got[:min(80, len(got))])
	}
}

// The diff is an edit script: applying it to the old text must give the new
// text. Checked against git's patch applier on awkward inputs.
func TestDiffsApplyCleanlyWithGitApply(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	inputs := [][2]string{
		{"one\ntwo\nthree\nfour\nfive\nsix\nseven\n", "one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\n"},
		{"a\nb\nc\n", "c\nb\na\n"},
		{"x\n", "x\nx\nx\n"},
		{"keep\nold1\nold2\nkeep2\n", "keep\nkeep2\n"},
		{"é中\nline\n", "é中\nlíne\n"},
	}
	for i, in := range inputs {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte(in[0]), 0o644); err != nil {
			t.Fatal(err)
		}
		patch := Unified("f", []byte(in[0]), []byte(in[1]), 3)
		if err := os.WriteFile(filepath.Join(dir, "p.diff"), []byte(patch), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("git", "apply", "--unsafe-paths", "p.diff")
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("case %d: git apply: %v\n%s\npatch:\n%s", i, err, out, patch)
		}
		got, _ := os.ReadFile(filepath.Join(dir, "f"))
		if string(got) != in[1] {
			t.Fatalf("case %d: applying the diff gave %q, want %q", i, got, in[1])
		}
	}
}
