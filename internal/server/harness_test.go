package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
