package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/server"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
	"github.com/mindfire-test/meiosis/pkg/worlds"
)

var meiBinary string

// TestMain builds the mei binary once: the receive hooks the server installs
// run it, so these tests exercise the real hook path, not a stand-in.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Fprintln(os.Stderr, "git is not installed; skipping server tests")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "mei-server-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	meiBinary = filepath.Join(dir, "mei")
	build := exec.Command("go", "build", "-o", meiBinary, "github.com/mindfire-test/meiosis/cmd/mei")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build mei: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// cleanEnv isolates git from the developer's configuration and from prompts.
func cleanEnv(home string) []string {
	return append(os.Environ(),
		"HOME="+home, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=dev@example.com", "GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=dev@example.com",
	)
}

type env struct {
	t       *testing.T
	root    string // the project directory `mei init` ran in
	home    string
	url     string // server URL
	repoURL string
	srv     *server.Server
	http    *httptest.Server
	human   crypto.KeyPair
	agent   crypto.KeyPair
	store   *graph.Store
}

type options struct {
	unauthenticated bool
	secrets         string
}

func newEnv(t *testing.T, o options) *env {
	t.Helper()
	e := &env{t: t, root: filepath.Join(t.TempDir(), "proj"), home: t.TempDir()}
	if err := os.MkdirAll(e.root, 0o755); err != nil {
		t.Fatal(err)
	}
	e.mei("init", "--repo", e.root, "--ide", "none")
	e.human = loadKeys(t, filepath.Join(e.root, ".meiosis", "human.private.key"))
	e.agent = loadKeys(t, filepath.Join(e.root, ".meiosis", "agent.private.key"))

	issuer := filepath.Join(e.root, ".meiosis", "human.public.key")
	if o.unauthenticated {
		issuer = ""
	}
	srv, err := server.New(server.Config{
		ReposDir: filepath.Join(e.root, ".meiosis", "git"), Repos: []string{"proj"},
		DB: filepath.Join(e.root, ".meiosis", "meiosisd.db"), Mei: meiBinary,
		SignerKeyPath: filepath.Join(e.root, ".meiosis", "human.private.key"), Signer: "human:tester",
		IssuerKeyPath: issuer, Strict: issuer != "", Secrets: o.secrets,
		Agent: "agent:meiosis", AgentKeyPath: filepath.Join(e.root, ".meiosis", "agent.private.key"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	e.srv, e.store = srv, srv.Store()
	e.http = httptest.NewServer(srv.Handler())
	t.Cleanup(func() { e.http.Close(); _ = srv.Close() })
	e.url = e.http.URL
	e.repoURL = e.url + "/proj.git"
	return e
}

func loadKeys(t *testing.T, path string) crypto.KeyPair {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k, err := crypto.LoadEncodedKeyPair(string(data), "")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mei runs the built binary and fails the test on error.
func (e *env) mei(args ...string) string {
	e.t.Helper()
	out, err := e.meiRun(args...)
	if err != nil {
		e.t.Fatalf("mei %v: %v\n%s", args, err, out)
	}
	return out
}

func (e *env) meiRun(args ...string) (string, error) {
	cmd := exec.Command(meiBinary, args...)
	cmd.Env = cleanEnv(e.home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String() + stderr.String(), err
}

// A workdir is a clone-to-be: a plain git repository with commits.
type workdir struct {
	e   *env
	dir string
}

func (e *env) workdir() *workdir {
	e.t.Helper()
	w := &workdir{e: e, dir: filepath.Join(e.t.TempDir(), "work")}
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	w.git("init", "-q", "-b", "main")
	return w
}

func (w *workdir) gitRun(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = w.dir
	cmd.Env = cleanEnv(w.e.home)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (w *workdir) git(args ...string) string {
	w.e.t.Helper()
	out, err := w.gitRun(args...)
	if err != nil {
		w.e.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(out)
}

func (w *workdir) write(name, content string) {
	w.e.t.Helper()
	full := filepath.Join(w.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		w.e.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		w.e.t.Fatal(err)
	}
}

func (w *workdir) commit(msg string) string {
	w.e.t.Helper()
	w.git("add", "-A")
	w.git("commit", "-q", "-m", msg)
	return w.git("rev-parse", "HEAD")
}

// push pushes with a bearer token in the Authorization header.
func (w *workdir) push(token string, args ...string) (string, error) {
	full := []string{}
	if token != "" {
		full = append(full, "-c", "http.extraHeader=Authorization: Bearer "+token)
	}
	full = append(full, "push")
	full = append(full, args...)
	return w.gitRun(full...)
}

// unauthorized reports whether a git failure was the server refusing the
// credentials: git either shows the 401, or, with prompts disabled, says it
// could not ask for a username after being challenged.
func unauthorized(out string) bool {
	return strings.Contains(out, "401") || strings.Contains(out, "could not read Username")
}

func bearer(t *testing.T, tok specv1.CapabilityToken) string {
	t.Helper()
	b, err := identity.Bearer(tok)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// agentToken is the root token `mei init` issued to the agent.
func (e *env) agentToken() specv1.CapabilityToken {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.root, ".agents", "meiosis-capability.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	tok, err := identity.Decode(data)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// humanToken issues a root token from the human key with the given limits.
func (e *env) humanToken(mutate func(*identity.IssueParams)) specv1.CapabilityToken {
	e.t.Helper()
	p := identity.IssueParams{
		Principal: "human:tester", IssuedBy: "human:tester", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}, HolderKey: e.human.PublicKey, TTL: time.Hour,
	}
	if mutate != nil {
		mutate(&p)
	}
	tok, err := identity.Issue(p, e.human.PrivateKey)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) refUpdates() []specv1.RefUpdate {
	e.t.Helper()
	updates, err := e.store.ListRefUpdates(context.Background(), "", "")
	if err != nil {
		e.t.Fatal(err)
	}
	return updates
}

func (e *env) declareIntent(mode string, files ...string) string {
	e.t.Helper()
	args := []string{"intent", "declare", "Work in scope", "--repo", e.root, "--created-by", "human:tester", "--mode", mode, "--format", "json"}
	for _, f := range files {
		args = append(args, "--files", f)
	}
	out := e.mei(args...)
	var intent map[string]any
	if err := json.Unmarshal([]byte(out), &intent); err != nil {
		e.t.Fatalf("declare: %v\n%s", err, out)
	}
	return intent["id"].(string)
}

func expectedWorld(t *testing.T, files map[string]string) specv1.WorldHash {
	t.Helper()
	mem := map[string][]byte{}
	for k, v := range files {
		mem[k] = []byte(v)
	}
	tree, err := worlds.NewMemoryTree(mem)
	if err != nil {
		t.Fatal(err)
	}
	w, err := worlds.New(context.Background(), tree)
	if err != nil {
		t.Fatal(err)
	}
	return w.Hash()
}

// ---- unauthenticated: the solo-developer path (IF-1) -------------------------

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
	bad, _ := identity.Issue(identity.IssueParams{Principal: "agent:evil", IssuedBy: "human:mallory", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}}, stranger.PrivateKey)
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

func rpc(t *testing.T, e *env, body string, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.url+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

func TestMCPEndpointServesToolsOverHTTPWithTheSameTokenChecks(t *testing.T) {
	e := newEnv(t, options{})

	if resp, body := rpc(t, e, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "attempt_open") {
		t.Fatalf("tools/list = %d %s", resp.StatusCode, body)
	}

	tok, err := json.Marshal(e.agentToken())
	if err != nil {
		t.Fatal(err)
	}
	call := func(args string) string {
		_, body := rpc(t, e, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"attempt_open","arguments":`+args+`}}`, nil)
		return body
	}
	if body := call(`{"task":"no token"}`); !strings.Contains(body, "capability_token is required") {
		t.Fatalf("a tool call with no token = %s", body)
	}
	body := call(`{"task":"over http","capability_token":` + string(tok) + `}`)
	if strings.Contains(body, `"isError":true`) || !strings.Contains(body, "derived_intent") {
		t.Fatalf("a tool call with a token = %s", body)
	}

	if resp, _ := rpc(t, e, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("a notification = %d, want 202", resp.StatusCode)
	}
	if resp, _ := rpc(t, e, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a batch = %d, want 400", resp.StatusCode)
	}
	if resp, _ := rpc(t, e, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Origin": "http://evil.example"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-origin request = %d, want 403", resp.StatusCode)
	}
	resp, err := http.Get(e.url + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp = %d, want 405", resp.StatusCode)
	}
}

func TestHealthzAndUnknownPaths(t *testing.T) {
	e := newEnv(t, options{})
	for path, want := range map[string]int{"/healthz": 200, "/nope": 404, "/missing.git/info/refs?service=git-upload-pack": 404, "/..%2f..%2fetc/passwd": 404} {
		resp, err := http.Get(e.url + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestStrictServerRefusesToRunWithoutAnIssuerKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	kp, _ := crypto.GenerateKeyPair()
	_ = os.WriteFile(key, []byte(kp.PrivateKeyBase64()), 0o600)
	_, err := server.New(server.Config{
		ReposDir: filepath.Join(dir, "git"), Repos: []string{"x"}, DB: filepath.Join(dir, "db"), Mei: meiBinary,
		SignerKeyPath: key, Signer: "human:t", Strict: true,
	})
	if err == nil || !strings.Contains(err.Error(), "strict") {
		t.Fatalf("New() = %v, want a refusal", err)
	}
	_ = sqlite.Open
}

func TestHooksAreReinstalledOnEveryStart(t *testing.T) {
	e := newEnv(t, options{})
	hook := filepath.Join(e.root, ".meiosis", "git", "proj.git", "hooks", "pre-receive")
	data, err := os.ReadFile(hook)
	if err != nil || !strings.Contains(string(data), meiBinary) {
		t.Fatalf("pre-receive hook = %q, %v", data, err)
	}
}

func TestAPIAndMetricsAreServedAlongsideGit(t *testing.T) {
	e := newEnv(t, options{})
	bearerTok := bearer(t, e.agentToken())

	post := func(path, body string, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, e.url+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearerTok)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	hdr := map[string]string{"Idempotency-Key": "api-1"}
	status, first := post("/api/v1/tools/attempt_open", `{"task":"through the REST API"}`, hdr)
	if status != 200 || !strings.Contains(first, `"idempotent_replay":false`) {
		t.Fatalf("API call: %d %s", status, first)
	}
	if status, again := post("/api/v1/tools/attempt_open", `{"task":"through the REST API"}`, hdr); status != 200 || !strings.Contains(again, `"idempotent_replay":true`) {
		t.Fatalf("API retry: %d %s", status, again)
	}
	if status, _ := post("/api/v1/tools/attempt_open", `{"task":"x"}`, map[string]string{"Authorization": "Bearer nonsense"}); status != 401 {
		t.Fatalf("API with a bad token: %d", status)
	}
	// A git request, refused for lack of credentials, also counts.
	resp, err := http.Get(e.url + "/proj.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	metricsResp, err := http.Get(e.url + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = metricsResp.Body.Close() }()
	body, _ := io.ReadAll(metricsResp.Body)
	text := string(body)
	for _, want := range []string{
		"meiosis_up 1", `meiosis_build_info{version="dev"} 1`,
		`meiosis_http_requests_total{route="api",code="200"} 2`, `meiosis_http_requests_total{route="api",code="401"} 1`,
		`meiosis_http_requests_total{route="git",code="401"} 1`,
		`meiosis_tool_calls_total{tool="attempt_open",outcome="ok"} 2`,
		`meiosis_http_request_duration_seconds_count{route="api"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/metrics missing %q:\n%s", want, text)
		}
	}
	// Nothing the clients controlled became a label.
	if strings.Contains(text, "nonsense") || strings.Contains(text, "api-1") {
		t.Errorf("a client-supplied value leaked into the metrics:\n%s", text)
	}
}
