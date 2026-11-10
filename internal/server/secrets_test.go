package server_test

import (
	"strings"
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// Assembled from parts so this file does not itself look like a leak.
var (
	fakeAWS    = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeGitHub = "ghp_" + strings.Repeat("A1b2", 9)
)

func pushWithFile(e *env, name, content string, args ...string) (*workdir, string, error) {
	w := e.workdir()
	w.write("README.md", "clean\n")
	w.write(name, content)
	w.commit("add " + name)
	w.git("remote", "add", "origin", e.repoURL)
	out, err := w.push(bearer(e.t, e.agentToken()), append(args, "origin", "main")...)
	return w, out, err
}

func TestAPushWithACredentialIsAcceptedInWarnModeButFlaggedAndRecorded(t *testing.T) {
	e := newEnv(t, options{}) // the default mode is warn
	_, out, err := pushWithFile(e, "deploy/config.go", "package deploy\n\nconst key = \""+fakeAWS+"\"\n")
	if err != nil {
		t.Fatalf("warn mode must not refuse the push: %v\n%s", err, out)
	}
	for _, want := range []string{"WARNING", "deploy/config.go:3", "aws-access-key-id", "not blocked"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, fakeAWS) {
		t.Fatalf("the warning repeated the secret:\n%s", out)
	}

	u := e.refUpdates()[0]
	if u.SecretScan != "warn" || len(u.SecretFindings) != 1 {
		t.Fatalf("update = scan %q findings %+v", u.SecretScan, u.SecretFindings)
	}
	f := u.SecretFindings[0]
	if f.Path != "deploy/config.go" || f.Line != 3 || f.Rule != "aws-access-key-id" || f.Confidence != "high" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestBlockModeRefusesAPushWithAHighConfidenceCredentialAndNothingMoves(t *testing.T) {
	e := newEnv(t, options{secrets: "block"})
	_, out, err := pushWithFile(e, "app/token.txt", "token = "+fakeGitHub+"\n")
	if err == nil {
		t.Fatalf("a push with a credential was accepted in block mode:\n%s", out)
	}
	for _, want := range []string{"REJECTED", "app/token.txt:1", "github-token", "secrets: block", "rotate"} {
		if !strings.Contains(out, want) {
			t.Errorf("rejection missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, fakeGitHub) {
		t.Fatalf("the rejection repeated the secret:\n%s", out)
	}
	if n := len(e.refUpdates()); n != 0 {
		t.Fatalf("a refused push recorded %d updates", n)
	}
	if ls := lsRemote(t, e, bearer(t, e.agentToken())); strings.Contains(ls, "refs/heads/main") {
		t.Fatalf("the ref moved despite the rejection:\n%s", ls)
	}
}

func TestBlockModeOnlyBlocksWhatItIsSureOf(t *testing.T) {
	e := newEnv(t, options{secrets: "block"})
	// A "possible" match (a long literal assigned to a secret-looking name) is
	// reported, not blocked.
	_, out, err := pushWithFile(e, "src/settings.go", "var password = \""+strings.Repeat("a1", 15)+"\"\n")
	if err != nil {
		t.Fatalf("a low-confidence match must not block: %v\n%s", err, out)
	}
	if !strings.Contains(out, "generic-secret-assignment") {
		t.Errorf("it should still be reported:\n%s", out)
	}
	if u := e.refUpdates()[0]; len(u.SecretFindings) != 1 || u.SecretFindings[0].Confidence != "possible" {
		t.Fatalf("findings = %+v", u.SecretFindings)
	}
}

func TestCredentialFilesAreFlaggedByName(t *testing.T) {
	e := newEnv(t, options{secrets: "block"})
	_, out, err := pushWithFile(e, ".meiosis/human.private.key", "not even a recognisable format\n")
	if err == nil || !strings.Contains(out, "meiosis-private-state") {
		t.Fatalf("pushing meiosis's own private state should be blocked by name: %v\n%s", err, out)
	}
	// A .env is only "possible": reported, allowed.
	e2 := newEnv(t, options{secrets: "block"})
	if _, out, err = pushWithFile(e2, ".env", "DEBUG=1\n"); err != nil || !strings.Contains(out, "dotenv-file") {
		t.Fatalf(".env: %v\n%s", err, out)
	}
}

func TestACleanPushHasNoFindingsAndOffModeDoesNotScan(t *testing.T) {
	e := newEnv(t, options{})
	if _, out, err := pushWithFile(e, "main.go", "package main\n"); err != nil || strings.Contains(out, "WARNING") {
		t.Fatalf("clean push: %v\n%s", err, out)
	}
	if u := e.refUpdates()[0]; len(u.SecretFindings) != 0 || u.SecretScan != "warn" {
		t.Fatalf("update = %+v", u)
	}

	off := newEnv(t, options{secrets: "off"})
	_, out, err := pushWithFile(off, "k.txt", fakeAWS+"\n")
	if err != nil || strings.Contains(out, "WARNING") {
		t.Fatalf("off mode: %v\n%s", err, out)
	}
	if u := off.refUpdates()[0]; u.SecretScan != "off" || len(u.SecretFindings) != 0 {
		t.Fatalf("off-mode update = %+v", u)
	}
}

func TestOnlyTheCommitsAPushIntroducesAreScanned(t *testing.T) {
	e := newEnv(t, options{secrets: "warn"})
	w, _, err := pushWithFile(e, "old.txt", fakeAWS+"\n")
	if err != nil {
		t.Fatal(err)
	}
	// A later, clean push must not re-report the credential already in history.
	w.write("new.go", "package n\n")
	w.commit("clean follow-up")
	out, err := w.push(bearer(t, e.agentToken()), "origin", "main")
	if err != nil || strings.Contains(out, "WARNING") {
		t.Fatalf("follow-up push: %v\n%s", err, out)
	}
	updates := e.refUpdates()
	if len(updates[0].SecretFindings) != 1 || len(updates[1].SecretFindings) != 0 {
		t.Fatalf("findings per push = %d then %d, want 1 then 0", len(updates[0].SecretFindings), len(updates[1].SecretFindings))
	}
	_ = specv1.RefUpdate{}
}
