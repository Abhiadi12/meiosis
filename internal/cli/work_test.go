package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitProject is a git repository, with an initial commit, that mei init has run in.
func gitProject(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "Dev")
	t.Setenv("GIT_AUTHOR_EMAIL", "d@e.x")
	t.Setenv("GIT_COMMITTER_NAME", "Dev")
	t.Setenv("GIT_COMMITTER_EMAIL", "d@e.x")
	root := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	mustRun(t, "", "init", "--repo", root, "--ide", "none")
	writeRepoFile(t, root, "src/main.go", "package main\n")
	git("add", "-A")
	git("commit", "-q", "-m", "initial")
	return root
}

func TestWorkFlowFromStartThroughSubmitUndoAndFork(t *testing.T) {
	root := gitProject(t)
	intent := declareJSON(t, root, "Fix the parser", "--files", "src/**", "--deny", "src/secret/**")["id"].(string)

	out := mustRun(t, "", "work", "start", intent[:14], "--repo", root)
	if !strings.Contains(out, "opened by human:") {
		t.Fatalf("start: %s", out)
	}
	if _, err := os.Stat(filepath.Join(root, ".meiosis", "work.json")); err != nil {
		t.Fatalf("work state not saved: %v", err)
	}

	// Edit inside scope, add a stray file outside it, delete a tracked one.
	writeRepoFile(t, root, "src/main.go", "package main\n\nfunc main() {}\n")
	writeRepoFile(t, root, "notes/todo.md", "stray")
	status := mustRun(t, "", "work", "status", "--repo", root)
	for _, want := range []string{"2 changed path(s)", "ok  change src/main.go", "OUT  change notes/todo.md", "matches no allow rule", "will refuse"} {
		if !strings.Contains(status, want) {
			t.Errorf("status missing %q:\n%s", want, status)
		}
	}

	// Submit refuses everything while one path is out of scope, and writes nothing.
	if _, err := run("", "work", "submit", "--repo", root); err == nil || !strings.Contains(err.Error(), "nothing was submitted") || !strings.Contains(err.Error(), "notes/todo.md") {
		t.Fatalf("submit with an out-of-scope path = %v", err)
	}
	if ops := mustRun(t, "", "op", "log", "--repo", root); strings.Contains(ops, "write") {
		t.Fatalf("a refused submit still wrote:\n%s", ops)
	}

	// Remove the stray file and submit.
	if err := os.RemoveAll(filepath.Join(root, "notes")); err != nil {
		t.Fatal(err)
	}
	submitted := mustRun(t, "", "work", "submit", "--repo", root, "--format", "json")
	var res struct {
		Attempt string   `json:"attempt"`
		World   string   `json:"world"`
		Changed []string `json:"changed"`
	}
	if err := json.Unmarshal([]byte(submitted), &res); err != nil || res.World == "" || len(res.Changed) != 1 || res.Changed[0] != "src/main.go" {
		t.Fatalf("submit: %v\n%s", err, submitted)
	}

	shown := mustRun(t, "", "attempt", "show", res.Attempt[:14], "--repo", root)
	for _, want := range []string{"human:", "mei work submit", "src/main.go", res.World} {
		if !strings.Contains(shown, want) {
			t.Errorf("attempt show missing %q:\n%s", want, shown)
		}
	}

	// The log has every step; undo restores the world from before the commit.
	log := mustRun(t, "", "op", "log", "--repo", root)
	for _, want := range []string{"open", "write", "commit", "src/main.go"} {
		if !strings.Contains(log, want) {
			t.Errorf("op log missing %q:\n%s", want, log)
		}
	}
	undone := mustRun(t, "", "op", "undo", "--repo", root)
	if !strings.Contains(undone, "undid") || strings.Contains(undone, res.World[:12]) {
		t.Fatalf("undo: %s", undone)
	}
	if redone := mustRun(t, "", "op", "undo", "--repo", root); !strings.Contains(redone, res.World) {
		t.Fatalf("undoing the undo should bring %s back: %s", res.World, redone)
	}
	if _, err := run("", "op", "undo", "--op", "op_nope", "--repo", root); err == nil {
		t.Fatal("undoing an unknown operation succeeded")
	}

	// Fork switches to a new attempt that starts with the same files.
	forkOut := mustRun(t, "", "work", "fork", "--repo", root)
	if !strings.Contains(forkOut, "forked") {
		t.Fatalf("fork: %s", forkOut)
	}
	state := mustRead(t, filepath.Join(root, ".meiosis", "work.json"))
	if strings.Contains(state, res.Attempt) {
		t.Fatalf("work.json still points at the original attempt:\n%s", state)
	}
	if shownFork := mustRun(t, "", "attempt", "list", "--repo", root); strings.Count(shownFork, "human:") != 2 {
		t.Fatalf("attempt list should show both attempts:\n%s", shownFork)
	}
}

func TestWorkStartNeedsExactlyOneOfIntentOrTaskAndSubmitNeedsChanges(t *testing.T) {
	root := gitProject(t)
	if _, err := run("", "work", "start", "--repo", root); err == nil {
		t.Error("work start with neither an intent nor a task was accepted")
	}
	if _, err := run("", "work", "submit", "--repo", root); err == nil || !strings.Contains(err.Error(), "no attempt in progress") {
		t.Errorf("submit before start = %v", err)
	}
	out := mustRun(t, "", "work", "start", "--task", "Tidy the parser", "--repo", root)
	if !strings.Contains(out, "opened by") {
		t.Fatalf("start --task: %s", out)
	}
	if _, err := run("", "work", "submit", "--repo", root); err == nil || !strings.Contains(err.Error(), "nothing to submit") {
		t.Errorf("submit with a clean tree = %v", err)
	}
	// A derived intent's scope is warn mode: out-of-scope paths are not blocked, and none exist.
	writeRepoFile(t, root, "anything/at/all.txt", "x")
	if res := mustRun(t, "", "work", "submit", "--repo", root); !strings.Contains(res, "submitted 1 path(s)") {
		t.Fatalf("submit: %s", res)
	}
}

func TestWorkSubmitRecordsDeletionsAndSaysWhenTheyCannotChangeTheWorld(t *testing.T) {
	root := gitProject(t)
	intent := declareJSON(t, root, "Cleanup", "--files", "src/**")["id"].(string)
	mustRun(t, "", "work", "start", intent, "--repo", root)
	if err := os.Remove(filepath.Join(root, "src", "main.go")); err != nil {
		t.Fatal(err)
	}

	status := mustRun(t, "", "work", "status", "--repo", root)
	if !strings.Contains(status, "delete src/main.go") || strings.Contains(status, ".meiosis") {
		t.Fatalf("status:\n%s", status)
	}
	res := mustRun(t, "", "work", "submit", "--repo", root)
	if !strings.Contains(res, "submitted 1 path(s)") {
		t.Fatalf("submit: %s", res)
	}
	// Attempts start from an empty base in this release, so deleting a file the
	// base never had cannot change the world; the user is told rather than misled.
	if !strings.Contains(res, "empty base") {
		t.Fatalf("submit should explain that the deletion has no effect on the world:\n%s", res)
	}
	if log := mustRun(t, "", "op", "log", "--repo", root); !strings.Contains(log, "delete") {
		t.Fatalf("a deletion should still be a logged operation:\n%s", log)
	}
}
