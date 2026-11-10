package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/server"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

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
