package acceptance

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The air-gap check is only worth something if it can fail, so first show that
// it does: a process with a wildcard listener and a connection to a non-loopback
// address is flagged, and a loopback-only one is not.
func TestTheSocketCheckCanActuallyFail(t *testing.T) {
	flagged := nonLoopback([]connection{
		{local: "127.0.0.1:50000", remote: "93.184.216.34:443", state: "ESTABLISHED"},
		{local: "*:8484", state: "LISTEN"},
		{local: "[::]:8484", state: "LISTEN"},
		{local: "10.0.0.5:8484", state: "LISTEN"},
	})
	if len(flagged) != 4 {
		t.Fatalf("flagged = %q, want the outbound connection and the three non-loopback listeners (and not more)", flagged)
	}
	clean := nonLoopback([]connection{
		{local: "127.0.0.1:50000", remote: "127.0.0.1:8484", state: "ESTABLISHED"},
		{local: "127.0.0.1:8484", state: "LISTEN"},
		{local: "[::1]:8484", state: "LISTEN"},
	})
	if len(clean) != 0 {
		t.Fatalf("loopback-only sockets were flagged: %q", clean)
	}
}

func TestSocketInspectionSeesRealSockets(t *testing.T) {
	if _, err := exec.LookPath("lsof"); err != nil {
		t.Skip("lsof is not installed")
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	conns, ok := socketsOf(t, os.Getpid())
	if !ok {
		t.Skip("lsof unavailable")
	}
	if len(nonLoopback(conns)) == 0 {
		t.Fatalf("a wildcard listener in this process was not detected; sockets seen: %+v", conns)
	}
}

// NFR-5.1: the binaries are built without cgo in TestMain, which already fails
// the whole package if that does not work. This checks the result is what it
// claims to be: no dynamic C library linkage of its own.
func TestBinariesAreBuiltWithoutCgo(t *testing.T) {
	out, err := exec.Command("go", "version", "-m", meiBin).CombinedOutput()
	if err != nil {
		t.Fatalf("go version -m: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "CGO_ENABLED=0") {
		t.Fatalf("mei was not built with CGO_ENABLED=0:\n%s", out)
	}
}

// RK-8: a self-hosted tool with a huge dependency tree does not get installed.
// The SRS budget is fewer than 40 direct modules.
func TestDirectDependencyBudget(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	direct := 0
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case line == ")":
			inBlock = false
		case strings.HasPrefix(line, "require ") && !strings.Contains(line, "// indirect"):
			direct++
		case inBlock && line != "" && !strings.HasPrefix(line, "//") && !strings.Contains(line, "// indirect"):
			direct++
		}
	}
	t.Logf("%d direct modules", direct)
	if direct >= 40 {
		t.Fatalf("go.mod has %d direct modules; the budget is fewer than 40 (RK-8)", direct)
	}
}

var bannedOutbound = []string{"http.Get(", "http.Post(", "http.NewRequest", "http.DefaultClient", "http.Client{", "net.Dial", "(&net.Dialer", "websocket"}

// outboundCalls lists the calls in source that open an outgoing connection.
func outboundCalls(source string) []string {
	var found []string
	for _, b := range bannedOutbound {
		if strings.Contains(source, b) {
			found = append(found, b)
		}
	}
	return found
}

func TestTheOutboundCodeCheckCanActuallyFail(t *testing.T) {
	if got := outboundCalls(`resp, _ := http.Get("https://telemetry.example/ping")`); len(got) != 1 {
		t.Fatalf("an http.Get was not flagged: %v", got)
	}
	if got := outboundCalls(`conn, _ := net.Dial("tcp", "x:1")`); len(got) == 0 {
		t.Fatal("a net.Dial was not flagged")
	}
	if got := outboundCalls(`ln, _ := net.Listen("tcp", addr); srv := &http.Server{}`); len(got) != 0 {
		t.Fatalf("listening was flagged: %v", got)
	}
}

// NFR-4.5 also says no telemetry and no licence check. Nothing in the shipped
// code may reach for an HTTP client or dial out: the only networking is
// listening, and the git handler that serves requests.
func TestNoOutboundNetworkCodeInTheShippedPackages(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "testdata", "acceptance", "bin", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, b := range outboundCalls(string(data)) {
			offenders = append(offenders, path+": "+b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("shipped code reaches for outbound networking (NFR-4.5):\n%s", strings.Join(offenders, "\n"))
	}
}
