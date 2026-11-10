package gitserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSmartHTTPCloneFetchPushAndPull(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	remote := filepath.Join(root, "repo.git")
	gitCommand(t, root, "init", "--bare", remote)

	seed := filepath.Join(root, "seed")
	gitCommand(t, root, "init", seed)
	gitCommand(t, seed, "config", "user.name", "Meiosis Test")
	gitCommand(t, seed, "config", "user.email", "test@example.com")
	writeTestFile(t, filepath.Join(seed, "README.md"), "initial\n")
	gitCommand(t, seed, "add", "README.md")
	gitCommand(t, seed, "commit", "-m", "initial")
	gitCommand(t, seed, "remote", "add", "origin", remote)
	gitCommand(t, seed, "push", "origin", "HEAD:main")
	gitCommand(t, root, "--git-dir", remote, "symbolic-ref", "HEAD", "refs/heads/main")

	handler, err := NewHandler(root)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	defer func() { _ = listener.Close() }()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	remoteURL := server.URL + "/repo.git"

	fetch := filepath.Join(root, "fetch")
	gitCommand(t, root, "clone", remoteURL, fetch)

	clone := filepath.Join(root, "clone")
	gitCommand(t, root, "clone", remoteURL, clone)
	gitCommand(t, clone, "config", "user.name", "Meiosis Test")
	gitCommand(t, clone, "config", "user.email", "test@example.com")
	writeTestFile(t, filepath.Join(clone, "README.md"), "pushed\n")
	gitCommand(t, clone, "commit", "-am", "update")
	gitCommand(t, clone, "push", "origin", "HEAD:main")

	gitCommand(t, fetch, "pull", "origin", "main")
	if got := readTestFile(t, filepath.Join(fetch, "README.md")); got != "pushed\n" {
		t.Fatalf("pull did not update the working tree: %q", got)
	}
}

func TestSmartHTTPRejectsTraversalPath(t *testing.T) {
	handler, err := NewHandler(t.TempDir())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/../secret/info/refs", nil)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 400 {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func gitCommand(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
