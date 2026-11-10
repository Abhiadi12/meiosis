package server_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestEnforcedIntentScopeRejectsAnOutOfScopePushAndNothingMoves(t *testing.T) {
	e := newEnv(t, options{})
	intent := e.declareIntent("enforce", "src/**")
	w := e.workdir()
	w.write("src/a.go", "package a")
	w.write("docs/notes.md", "notes")
	w.commit("touches docs too")
	w.git("remote", "add", "origin", e.repoURL)

	out, err := w.push(bearer(t, e.agentToken()), "-o", "intent="+intent, "origin", "main")
	if err == nil {
		t.Fatalf("an out-of-scope push was accepted:\n%s", out)
	}
	for _, want := range []string{"REJECTED", "docs/notes.md", "outside the scope of intent " + intent, "mode enforce"} {
		if !strings.Contains(out, want) {
			t.Errorf("rejection message missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "src/a.go is") || strings.Contains(out, "src/a.go,") {
		t.Errorf("the in-scope path should not be blamed:\n%s", out)
	}
	if n := len(e.refUpdates()); n != 0 {
		t.Fatalf("a rejected push recorded %d updates", n)
	}
	if ls := lsRemote(t, e, bearer(t, e.agentToken())); strings.Contains(ls, "refs/heads/main") {
		t.Fatalf("the ref moved despite the rejection:\n%s", ls)
	}

	// Remove the stray file and push again: accepted, under that intent.
	w.git("rm", "-q", "-r", "docs")
	w.git("commit", "-q", "--amend", "-m", "src only")
	if out, err = w.push(bearer(t, e.agentToken()), "-o", "intent="+intent, "origin", "main"); err != nil {
		t.Fatalf("in-scope push: %v\n%s", err, out)
	}
	u := e.refUpdates()[0]
	if u.Intent != intent || u.ImplicitIntent {
		t.Fatalf("update = %+v, want the named intent", u)
	}
}

func lsRemote(t *testing.T, e *env, token string) string {
	t.Helper()
	cmd := exec.Command("git", "-c", "http.extraHeader=Authorization: Bearer "+token, "ls-remote", e.repoURL)
	cmd.Env = cleanEnv(e.home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ls-remote: %v\n%s", err, out)
	}
	return string(out)
}

func TestWarnModeIntentAcceptsAnOutOfScopePushAndRecordsTheViolations(t *testing.T) {
	e := newEnv(t, options{})
	intent := e.declareIntent("warn", "src/**")
	w := e.workdir()
	w.write("src/a.go", "package a")
	w.write("docs/notes.md", "notes")
	w.commit("mixed")
	w.git("remote", "add", "origin", e.repoURL)

	out, err := w.push(bearer(t, e.agentToken()), "-o", "intent="+intent, "origin", "main")
	if err != nil {
		t.Fatalf("a warn-mode push should be accepted: %v\n%s", err, out)
	}
	if !strings.Contains(out, "recorded as violations") {
		t.Errorf("output should mention the recorded violation:\n%s", out)
	}
	u := e.refUpdates()[0]
	if len(u.ScopeViolations) != 1 || u.ScopeViolations[0].Path != "docs/notes.md" {
		t.Fatalf("ScopeViolations = %+v", u.ScopeViolations)
	}
}

func TestATokensOwnScopeBindsPushes(t *testing.T) {
	e := newEnv(t, options{})
	w := e.workdir()
	w.write("src/a.go", "package a")
	w.write("secrets/key", "k")
	w.commit("touches secrets")
	w.git("remote", "add", "origin", e.repoURL)

	narrow := e.humanToken(func(p *identity.IssueParams) {
		p.Scope = specv1.Scope{Allow: []string{"src/**"}, Mode: specv1.ScopeModeEnforce}
	})
	out, err := w.push(bearer(t, narrow), "origin", "main")
	if err == nil || !strings.Contains(out, "secrets/key") || !strings.Contains(out, "scope of your capability token") {
		t.Fatalf("a push outside the token's scope = %v\n%s", err, out)
	}
	if n := len(e.refUpdates()); n != 0 {
		t.Fatalf("recorded %d updates", n)
	}
}

func TestADelegatedTokensNarrowedScopeIsEnforcedOnPush(t *testing.T) {
	e := newEnv(t, options{})
	childPath := filepath.Join(t.TempDir(), "child.json")
	e.mei("intent", "delegate", "--repo", e.root,
		"--token", filepath.Join(e.root, ".agents", "meiosis-capability.json"), "--key", filepath.Join(e.root, ".meiosis", "agent.private.key"),
		"--to", "agent:sub", "--generate-key", filepath.Join(t.TempDir(), "sub.key"), "--allow", "src/auth/**", "--out", childPath)
	data, err := os.ReadFile(childPath)
	if err != nil {
		t.Fatal(err)
	}
	child, err := identity.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	w := e.workdir()
	w.write("src/auth/login.go", "package auth")
	w.write("src/billing/x.go", "package billing")
	w.commit("two areas")
	w.git("remote", "add", "origin", e.repoURL)
	if out, err := w.push(bearer(t, child), "origin", "main"); err == nil || !strings.Contains(out, "src/billing/x.go") {
		t.Fatalf("a delegated token pushing outside its narrowed scope = %v\n%s", err, out)
	}
	w.git("rm", "-q", "-r", "src/billing")
	w.git("commit", "-q", "--amend", "-m", "auth only")
	if out, err := w.push(bearer(t, child), "origin", "main"); err != nil {
		t.Fatalf("in-scope push with the delegated token: %v\n%s", err, out)
	}
	u := e.refUpdates()[0]
	if u.PushedBy != "agent:sub" || u.Token == nil || u.Token.Depth() != 1 || identity.Origin(*u.Token) == "" {
		t.Fatalf("update = %+v", u)
	}
}

func TestATokenBoundToAnIntentPushesUnderIt(t *testing.T) {
	e := newEnv(t, options{})
	intent := e.declareIntent("enforce", "src/**")
	bound := e.humanToken(func(p *identity.IssueParams) { p.Intent = intent })
	w := e.workdir()
	w.write("src/a.go", "package a")
	w.commit("bound")
	w.git("remote", "add", "origin", e.repoURL)

	if out, err := w.push(bearer(t, bound), "origin", "main"); err != nil {
		t.Fatalf("push with an intent-bound token: %v\n%s", err, out)
	}
	if u := e.refUpdates()[0]; u.Intent != intent || u.ImplicitIntent {
		t.Fatalf("update = %+v, want the token's intent", u)
	}

	w.write("src/b.go", "package b")
	w.commit("again")
	other := "int_" + strings.Repeat("b", 52)
	if out, err := w.push(bearer(t, bound), "-o", "intent="+other, "origin", "main"); err == nil || !strings.Contains(out, "bound to") {
		t.Fatalf("naming a different intent than the token's = %v\n%s", err, out)
	}
}

func TestUnknownAndClosedIntentsAreRefused(t *testing.T) {
	e := newEnv(t, options{})
	intent := e.declareIntent("enforce", "src/**")
	w := e.workdir()
	w.write("src/a.go", "package a")
	w.commit("one")
	w.git("remote", "add", "origin", e.repoURL)
	tok := bearer(t, e.agentToken())

	if out, err := w.push(tok, "-o", "intent=int_nosuchintent", "origin", "main"); err == nil || !strings.Contains(out, "no intent matches") {
		t.Fatalf("an unknown intent = %v\n%s", err, out)
	}
	e.mei("intent", "supersede", intent, "Replacement", "--repo", e.root, "--created-by", "human:tester")
	if out, err := w.push(tok, "-o", "intent="+intent, "origin", "main"); err == nil || !strings.Contains(out, "not open for new work") {
		t.Fatalf("a superseded intent = %v\n%s", err, out)
	}
}

func TestAPushedTreeIsLinkedToTheAttemptThatProducedIt(t *testing.T) {
	e := newEnv(t, options{})
	intent := e.declareIntent("enforce", "src/**")
	ctx := context.Background()

	// An attempt writes and commits these files through the graph, as an agent does over MCP.
	attempt, err := e.store.OpenAttempt(ctx, graph.OpenAttemptParams{Intent: intent, Author: "agent:meiosis"}, e.agent.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{"src/a.go": "package a\n", "src/b.go": "package b\n"} {
		if _, err = e.store.WriteFile(ctx, graph.WriteParams{Attempt: attempt.ID, Author: "agent:meiosis", Path: path, Content: []byte(content)}, e.agent.PrivateKey); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := e.store.CommitAttempt(ctx, graph.CommitParams{Attempt: attempt.ID, Author: "agent:meiosis"}, e.agent.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	// The same files arrive through git.
	w := e.workdir()
	w.write("src/a.go", "package a\n")
	w.write("src/b.go", "package b\n")
	w.commit("the same tree")
	w.git("remote", "add", "origin", e.repoURL)
	if out, err := w.push(bearer(t, e.agentToken()), "-o", "intent="+intent, "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	u := e.refUpdates()[0]
	if u.World != committed.Attempt.World {
		t.Fatalf("pushed world %s != attempt world %s: the same files must hash identically however they arrive", u.World, committed.Attempt.World)
	}
	if u.Attempt != attempt.ID {
		t.Fatalf("RefUpdate.Attempt = %q, want %q", u.Attempt, attempt.ID)
	}
}

// ---- the MCP endpoint --------------------------------------------------------
