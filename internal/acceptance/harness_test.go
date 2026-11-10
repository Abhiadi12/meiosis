package acceptance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	meiBin      string
	meiosisdBin string
	buildTime   time.Duration
)

// TestMain builds both binaries once, with cgo off: that the build succeeds at
// all is the NFR-5.1 check, and everything below runs the artefacts a user would.
func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Fprintln(os.Stderr, "-short: skipping the acceptance suite (it builds and runs the real binaries)")
		os.Exit(0)
	}
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Fprintln(os.Stderr, "git is not installed; skipping acceptance tests")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "mei-acceptance")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	meiBin, meiosisdBin = filepath.Join(dir, "mei"), filepath.Join(dir, "meiosisd")
	start := time.Now()
	for bin, pkg := range map[string]string{meiBin: "github.com/mindfire-test/meiosis/cmd/mei", meiosisdBin: "github.com/mindfire-test/meiosis/cmd/meiosisd"} {
		cmd := exec.Command("go", "build", "-o", bin, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s without cgo: %v\n%s", pkg, err, out)
			os.Exit(1)
		}
	}
	buildTime = time.Since(start)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func isolatedEnv(home string) []string {
	return append(os.Environ(),
		"HOME="+home, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=dev@example.com", "GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=dev@example.com",
	)
}

// project is a git repository that `mei init` has been run in.
type project struct {
	t    *testing.T
	dir  string
	home string
}

func newProject(t *testing.T, initArgs ...string) *project {
	t.Helper()
	p := &project{t: t, dir: filepath.Join(t.TempDir(), "shop"), home: t.TempDir()}
	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p.git("init", "-q", "-b", "main")
	p.mei(append([]string{"init", "--ide", "none"}, initArgs...)...)
	return p
}

func (p *project) run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = p.dir
	cmd.Env = isolatedEnv(p.home)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (p *project) mei(args ...string) string {
	p.t.Helper()
	out, err := p.run(meiBin, args...)
	if err != nil {
		p.t.Fatalf("mei %v: %v\n%s", args, err, out)
	}
	return out
}

func (p *project) meiErr(args ...string) (string, error) { return p.run(meiBin, args...) }

func (p *project) git(args ...string) string {
	p.t.Helper()
	out, err := p.run("git", args...)
	if err != nil {
		p.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(out)
}

func (p *project) write(name, content string) {
	p.t.Helper()
	full := filepath.Join(p.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func (p *project) read(name string) []byte {
	p.t.Helper()
	data, err := os.ReadFile(filepath.Join(p.dir, filepath.FromSlash(name)))
	if err != nil {
		p.t.Fatal(err)
	}
	return data
}

// declare creates an intent as the human and returns its ID.
func (p *project) declare(title string, extra ...string) string {
	p.t.Helper()
	out := p.mei(append([]string{"intent", "declare", title, "--format", "json"}, extra...)...)
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.ID == "" {
		p.t.Fatalf("declare output: %v\n%s", err, out)
	}
	return v.ID
}

func (p *project) agentToken() map[string]any {
	p.t.Helper()
	var tok map[string]any
	if err := json.Unmarshal(p.read(".agents/meiosis-capability.json"), &tok); err != nil {
		p.t.Fatal(err)
	}
	return tok
}

// agent is a meiosisd process speaking MCP over stdio, started the way an IDE
// would start it from the config `mei init` writes.
type agent struct {
	t      *testing.T
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Scanner
	mu     sync.Mutex
	nextID int
	token  map[string]any
}

func (p *project) startAgent() *agent {
	p.t.Helper()
	cmd := exec.Command(meiosisdBin, "--principal", "agent:meiosis",
		"--key", filepath.Join(p.dir, ".meiosis", "agent.private.key"), "--db", filepath.Join(p.dir, ".meiosis", "meiosisd.db"))
	cmd.Dir = p.dir
	cmd.Env = isolatedEnv(p.home)
	in, err := cmd.StdinPipe()
	if err != nil {
		p.t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		p.t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	a := &agent{t: p.t, cmd: cmd, in: in, out: bufio.NewScanner(stdout), token: p.agentToken()}
	a.out.Buffer(make([]byte, 0, 1<<16), 8<<20)
	p.t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
	})
	return a
}

// call runs one tool with the agent's capability token and returns its decoded
// result, or the tool's error text.
func (a *agent) call(tool string, args map[string]any) (map[string]any, string) {
	a.t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextID++
	full := map[string]any{}
	for k, v := range args {
		full[k] = v
	}
	if _, ok := full["capability_token"]; !ok {
		full["capability_token"] = a.token
	}
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": a.nextID, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": full}})
	if err != nil {
		a.t.Fatal(err)
	}
	if _, err = a.in.Write(append(req, '\n')); err != nil {
		a.t.Fatalf("write to meiosisd: %v", err)
	}
	if !a.out.Scan() {
		a.t.Fatalf("meiosisd closed its output: %v", a.out.Err())
	}
	var resp struct {
		Result struct {
			IsError           bool                    `json:"isError"`
			StructuredContent map[string]any          `json:"structuredContent"`
			Content           []struct{ Text string } `json:"content"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err = json.Unmarshal(a.out.Bytes(), &resp); err != nil {
		a.t.Fatalf("decode %s: %v", a.out.Bytes(), err)
	}
	if resp.Error != nil {
		return nil, resp.Error.Message
	}
	if resp.Result.IsError {
		text := ""
		if len(resp.Result.Content) > 0 {
			text = resp.Result.Content[0].Text
		}
		return nil, text
	}
	return resp.Result.StructuredContent, ""
}

// must is call that fails the test on a tool error.
func (a *agent) must(tool string, args map[string]any) map[string]any {
	a.t.Helper()
	out, errText := a.call(tool, args)
	if errText != "" {
		a.t.Fatalf("%s: %s", tool, errText)
	}
	return out
}

func (a *agent) pid() int { return a.cmd.Process.Pid }

// server is `mei serve` running as a subprocess.
type server struct {
	cmd  *exec.Cmd
	url  string
	addr string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func (p *project) serve() *server {
	p.t.Helper()
	addr := freeAddr(p.t)
	cmd := exec.Command(meiBin, "serve", "--addr", addr)
	cmd.Dir = p.dir
	cmd.Env = isolatedEnv(p.home)
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	s := &server{cmd: cmd, addr: addr, url: "http://" + addr}
	p.t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(s.url + "/healthz"); err == nil {
			_ = resp.Body.Close()
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.t.Fatalf("mei serve did not come up on %s:\n%s", addr, log.String())
	return nil
}

const junitPass = `<testsuites><testsuite name="auth" tests="2">
  <testcase classname="auth.Login" name="TestRedirect" time="0.2"/>
  <testcase classname="auth.Login" name="TestNoLoop" time="0.1"/>
</testsuite></testsuites>`

const junitFail = `<testsuites><testsuite name="auth">
  <testcase classname="auth.Login" name="TestRedirect"><failure message="redirected to /home"/></testcase>
</testsuite></testsuites>`
