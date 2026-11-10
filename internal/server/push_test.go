package server_test

import (
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestAnonymousPushIsAcceptedUnderAnImplicitWarnIntentAndRecordsASignedWorld(t *testing.T) {
	e := newEnv(t, options{unauthenticated: true})
	w := e.workdir()
	w.write("README.md", "hello\n")
	w.write("src/a.go", "package a\n")
	c1 := w.commit("Initial commit")
	w.git("remote", "add", "origin", e.repoURL)

	out, err := w.push("", "origin", "main")
	if err != nil {
		t.Fatalf("anonymous push: %v\n%s", err, out)
	}
	for _, want := range []string{"meiosis: refs/heads/main accepted as human:anonymous", "implicit intent", "-> world"} {
		if !strings.Contains(out, want) {
			t.Errorf("push output missing %q:\n%s", want, out)
		}
	}

	updates := e.refUpdates()
	if len(updates) != 1 {
		t.Fatalf("ref updates = %d, want 1", len(updates))
	}
	u := updates[0]
	if u.NewCommit != c1 || u.OldCommit != "" || u.BaseWorld != nil || u.Ref != "refs/heads/main" || u.Repo != "proj" {
		t.Fatalf("update = %+v", u)
	}
	if want := expectedWorld(t, map[string]string{"README.md": "hello\n", "src/a.go": "package a\n"}); u.World != want {
		t.Fatalf("world = %s, want %s (the hash of the same files in an attempt)", u.World, want)
	}
	if !u.ImplicitIntent || u.PushedBy != "human:anonymous" || u.Token != nil || u.ChangedPaths != 2 {
		t.Fatalf("update = %+v", u)
	}
	if ok, verr := crypto.Verify(u, u.Signature, e.human.PublicKey); verr != nil || !ok || u.SignedBy != "human:tester" {
		t.Fatalf("the record is not signed by the server: %v %v", ok, verr)
	}
	view, err := e.store.GetIntentView(context.Background(), u.Intent)
	if err != nil || view.Scope.Mode != specv1.ScopeModeWarn || view.Scope.Allow[0] != "**" {
		t.Fatalf("implicit intent = %+v, %v; want scope mode warn over **", view, err)
	}

	// A second push is a new record that knows the world it moved from.
	w.write("src/a.go", "package a // v2\n")
	c2 := w.commit("Second")
	if out, err = w.push("", "origin", "main"); err != nil {
		t.Fatalf("second push: %v\n%s", err, out)
	}
	updates = e.refUpdates()
	if len(updates) != 2 || updates[1].OldCommit != c1 || updates[1].NewCommit != c2 {
		t.Fatalf("updates = %+v", updates)
	}
	if updates[1].BaseWorld == nil || *updates[1].BaseWorld != updates[0].World || updates[1].World == updates[0].World {
		t.Fatalf("second update's base world should be the first's world, and the world should have changed")
	}
	if updates[1].ChangedPaths != 1 {
		t.Fatalf("ChangedPaths = %d, want 1", updates[1].ChangedPaths)
	}

	// `mei refs` shows them, with signatures verifying against the human key.
	listing := e.mei("refs", "--repo", e.root)
	if strings.Count(listing, "verified") != 2 || !strings.Contains(listing, "(implicit)") {
		t.Fatalf("mei refs =\n%s", listing)
	}
}

func TestCloneAndPullWorkAgainstTheServer(t *testing.T) {
	e := newEnv(t, options{unauthenticated: true})
	w := e.workdir()
	w.write("a.txt", "one\n")
	w.commit("one")
	w.git("remote", "add", "origin", e.repoURL)
	if out, err := w.push("", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", e.repoURL, clone)
	cmd.Env = cleanEnv(e.home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(clone, "a.txt")); err != nil || string(data) != "one\n" {
		t.Fatalf("cloned file = %q, %v", data, err)
	}

	// FR-8.5: the git remote is a complete escape hatch: a plain clone has the
	// code and its history, and needs nothing from meiosis.
	log := exec.Command("git", "-C", clone, "log", "--oneline")
	log.Env = cleanEnv(e.home)
	if out, err := log.CombinedOutput(); err != nil || !strings.Contains(string(out), "one") {
		t.Fatalf("history = %q, %v", out, err)
	}
}

func TestEveryGitProtocolVersionWorks(t *testing.T) {
	e := newEnv(t, options{unauthenticated: true})
	seed := e.workdir()
	seed.write("a.txt", "seed\n")
	seed.commit("seed")
	seed.git("remote", "add", "origin", e.repoURL)
	if out, err := seed.push("", "origin", "main"); err != nil {
		t.Fatalf("seed push: %v\n%s", err, out)
	}

	for _, version := range []string{"0", "1", "2"} {
		t.Run("protocol.version="+version, func(t *testing.T) {
			clone := filepath.Join(t.TempDir(), "c")
			cmd := exec.Command("git", "-c", "protocol.version="+version, "clone", "-q", e.repoURL, clone)
			cmd.Env = append(cleanEnv(e.home), "GIT_TRACE_PACKET=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("clone: %v\n%s", err, out)
			}
			sawV2 := strings.Contains(string(out), "version 2")
			if version == "2" && !sawV2 {
				t.Fatalf("protocol.version=2 did not negotiate v2")
			}
			if version != "2" && sawV2 {
				t.Fatalf("protocol.version=%s unexpectedly negotiated v2", version)
			}

			// And push back over the same version.
			work := &workdir{e: e, dir: clone}
			work.write("v"+version+".txt", "pushed with protocol "+version+"\n")
			work.git("add", "-A")
			work.git("commit", "-q", "-m", "v"+version)
			pushed, err := work.gitRun("-c", "protocol.version="+version, "push", "origin", "main")
			if err != nil {
				t.Fatalf("push: %v\n%s", err, pushed)
			}
		})
	}
	if n := len(e.refUpdates()); n != 4 { // the seed plus one per version
		t.Fatalf("ref updates = %d, want 4", n)
	}
}

func TestLargePushOverChunkedTransferIsRecordedWithTheRightWorld(t *testing.T) {
	e := newEnv(t, options{unauthenticated: true})
	big := make([]byte, 6<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	w := e.workdir()
	w.write("small.txt", "s")
	if err := os.WriteFile(filepath.Join(w.dir, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	w.commit("big")
	w.git("remote", "add", "origin", e.repoURL)
	// Force git to buffer little so the request body is chunked.
	if out, err := w.gitRun("-c", "http.postBuffer=65536", "push", "origin", "main"); err != nil {
		t.Fatalf("large push: %v\n%s", err, out)
	}
	updates := e.refUpdates()
	if len(updates) != 1 {
		t.Fatalf("ref updates = %d", len(updates))
	}
	want := expectedWorld(t, map[string]string{"small.txt": "s", "big.bin": string(big)})
	if updates[0].World != want {
		t.Fatalf("world of a pushed 6 MiB file = %s, want %s", updates[0].World, want)
	}
}

func TestDeletingARefAndRewritingHistoryAreRefused(t *testing.T) {
	e := newEnv(t, options{unauthenticated: true})
	w := e.workdir()
	w.write("a", "1")
	w.commit("one")
	w.git("remote", "add", "origin", e.repoURL)
	if out, err := w.push("", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	w.write("a", "2")
	w.commit("two")
	if out, err := w.push("", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}

	if out, err := w.push("", "origin", "--delete", "main"); err == nil {
		t.Fatalf("deleting a ref succeeded:\n%s", out)
	}
	w.git("reset", "-q", "--hard", "HEAD~1")
	w.write("a", "rewritten")
	w.commit("rewrite")
	if out, err := w.push("", "--force", "origin", "main"); err == nil {
		t.Fatalf("a force push (history rewrite) succeeded:\n%s", out)
	}
	if n := len(e.refUpdates()); n != 2 {
		t.Fatalf("a refused push left %d ref updates, want the 2 accepted ones", n)
	}
}

// ---- authentication ------------------------------------------------------

func TestPushNeedsACapabilityToken(t *testing.T) {
	e := newEnv(t, options{})
	w := e.workdir()
	w.write("a", "1")
	w.commit("one")
	w.git("remote", "add", "origin", e.repoURL)

	if out, err := w.push("", "origin", "main"); err == nil || !unauthorized(out) {
		t.Fatalf("an unauthenticated push = %v\n%s, want a 401 challenge", err, out)
	}
	if out, err := w.push("garbage-token", "origin", "main"); err == nil || !unauthorized(out) {
		t.Fatalf("a malformed token = %v\n%s, want a 401", err, out)
	}
	// A token the issuer never signed.
	stranger, _ := crypto.GenerateKeyPair()
	bad, _ := identity.Issue(identity.IssueParams{
		Principal: "agent:evil", IssuedBy: "human:mallory", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
	}, stranger.PrivateKey)
	if out, err := w.push(bearer(t, bad), "origin", "main"); err == nil || !unauthorized(out) {
		t.Fatalf("a token from the wrong issuer = %v\n%s", err, out)
	}
	if n := len(e.refUpdates()); n != 0 {
		t.Fatalf("refused pushes recorded %d updates", n)
	}

	// Clone and fetch need a token as well.
	cmd := exec.Command("git", "clone", "-q", e.repoURL, filepath.Join(t.TempDir(), "c"))
	cmd.Env = cleanEnv(e.home)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("an unauthenticated clone succeeded:\n%s", out)
	}
}

func TestPushWithAnAgentTokenIsAttributedToTheAgentAndKeepsItsChain(t *testing.T) {
	e := newEnv(t, options{})
	w := e.workdir()
	w.write("src/a.go", "package a")
	w.commit("agent work")
	w.git("remote", "add", "origin", e.repoURL)

	tok := e.agentToken()
	out, err := w.push(bearer(t, tok), "origin", "main")
	if err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if !strings.Contains(out, "accepted as agent:meiosis") {
		t.Fatalf("output = %s", out)
	}
	u := e.refUpdates()[0]
	if u.PushedBy != "agent:meiosis" || u.Token == nil || u.Token.ID != tok.ID {
		t.Fatalf("update = %+v", u)
	}
	if identity.Origin(*u.Token) == "" || identity.Verify(*u.Token, e.human.PublicKey, nil, u.At) != nil {
		t.Fatal("the recorded token's chain does not verify back to the human")
	}
}

func TestACredentialHelperMakesPlainGitCommandsWork(t *testing.T) {
	e := newEnv(t, options{})
	// The project is itself a git repository, as it would be in real use.
	w := &workdir{e: e, dir: e.root}
	w.git("init", "-q", "-b", "main")
	e.mei("init", "--repo", e.root, "--ide", "none") // re-run so .gitignore now covers the secrets
	w.write("a.txt", "1")
	w.commit("one")

	out := e.mei("remote", "add", "meiosis", "--repo", e.root, "--url", e.repoURL)
	if !strings.Contains(out, "meiosis") {
		t.Fatalf("remote add output = %s", out)
	}
	if tracked := w.git("ls-files"); strings.Contains(tracked, ".meiosis") || strings.Contains(tracked, "meiosis-capability.json") {
		t.Fatalf("secrets were committed:\n%s", tracked)
	}

	if pushed, err := w.gitRun("push", "meiosis", "main"); err != nil {
		t.Fatalf("push through the credential helper: %v\n%s", err, pushed)
	}
	u := e.refUpdates()
	if len(u) != 1 || !strings.HasPrefix(u[0].PushedBy, "human:") || u[0].Token == nil || u[0].Token.ID == "" {
		t.Fatalf("updates = %+v", u)
	}
	if fetched, err := w.gitRun("fetch", "meiosis"); err != nil {
		t.Fatalf("fetch through the credential helper: %v\n%s", err, fetched)
	}
	// Two operations, two short-lived tokens: nothing is stored.
	w.write("a.txt", "2")
	w.commit("two")
	if pushed, err := w.gitRun("push", "meiosis", "main"); err != nil {
		t.Fatalf("second push: %v\n%s", err, pushed)
	}
}

func TestOperationsAndRevocationApplyToGit(t *testing.T) {
	e := newEnv(t, options{})
	w := e.workdir()
	w.write("a", "1")
	w.commit("one")
	w.git("remote", "add", "origin", e.repoURL)

	readOnly := e.humanToken(func(p *identity.IssueParams) { p.Operations = []string{"git_fetch"} })
	if out, err := w.push(bearer(t, readOnly), "origin", "main"); err == nil || !strings.Contains(out, "403") || !strings.Contains(out, "git_push") {
		t.Fatalf("pushing with a fetch-only token = %v\n%s, want a 403 naming git_push", err, out)
	}
	pushOnly := e.humanToken(func(p *identity.IssueParams) { p.Operations = []string{"git_push"} })
	cmd := exec.Command("git", "-c", "http.extraHeader=Authorization: Bearer "+bearer(t, pushOnly), "ls-remote", e.repoURL)
	cmd.Env = cleanEnv(e.home)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "403") {
		t.Fatalf("fetching with a push-only token = %v\n%s", err, out)
	}

	good := e.humanToken(nil)
	if out, err := w.push(bearer(t, good), "origin", "main"); err != nil {
		t.Fatalf("push with a full token: %v\n%s", err, out)
	}
	e.mei("intent", "revoke", good.ID, "--repo", e.root)
	w.write("a", "2")
	w.commit("two")
	if out, err := w.push(bearer(t, good), "origin", "main"); err == nil || !unauthorized(out) {
		t.Fatalf("pushing with a revoked token = %v\n%s", err, out)
	}
}

// ---- scope enforcement at push time (FR-3.4) -------------------------------
