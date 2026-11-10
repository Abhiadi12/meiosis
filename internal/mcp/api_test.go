package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mindfire-test/meiosis/internal/identity"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// api is a client for ServeAPI against a server.
type api struct {
	t   *testing.T
	srv *httptest.Server
}

func newAPI(t *testing.T, s *Server) *api {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(s.ServeAPI))
	t.Cleanup(ts.Close)
	return &api{t: t, srv: ts}
}

func (a *api) do(method, path string, body any, header map[string]string) (int, map[string]any, http.Header) {
	a.t.Helper()
	var rdr io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rdr = strings.NewReader(b)
		default:
			data, _ := json.Marshal(b)
			rdr = bytes.NewReader(data)
		}
	}
	req, err := http.NewRequest(method, a.srv.URL+path, rdr)
	if err != nil {
		a.t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out, resp.Header
}

func (a *api) post(tool string, body any, header map[string]string) (int, map[string]any) {
	status, out, _ := a.do(http.MethodPost, "/api/v1/tools/"+tool, body, header)
	return status, out
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func TestAPIListsOperationsAndMarksTheMutatingOnes(t *testing.T) {
	a := newAPI(t, newTestServer(t))
	status, out, _ := a.do(http.MethodGet, "/api/v1/tools", nil, nil)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	mutating := map[string]bool{}
	for _, tl := range out["tools"].([]any) {
		m := tl.(map[string]any)
		mutating[m["name"].(string)] = m["mutating"].(bool)
		if m["mutating"] == true {
			props := m["input_schema"].(map[string]any)["properties"].(map[string]any)
			if props["idempotency_key"] == nil {
				t.Errorf("%s is mutating but does not advertise idempotency_key", m["name"])
			}
		}
	}
	if !mutating["attempt_write"] || !mutating["workspace_undo"] || mutating["attempt_status"] || mutating["evidence_query"] {
		t.Fatalf("mutating flags = %v", mutating)
	}
}

func TestAPIStatusCodesSayWhatKindOfFailureItWas(t *testing.T) {
	s, issuer := enforcingServer(t)
	a := newAPI(t, s)
	repo := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	repoBearer := bearerOf(t, repo)
	narrow := mustIssue(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent, specv1.Scope{Allow: []string{"src/**"}, Mode: specv1.ScopeModeEnforce})

	// 200 with a bearer header standing in for the capability_token argument.
	status, out := a.post("attempt_open", map[string]any{"task": "via the API"}, map[string]string{"Authorization": "Bearer " + repoBearer})
	if status != 200 || out["result"].(map[string]any)["id"] == nil {
		t.Fatalf("attempt_open: %d %v", status, out)
	}
	attempt := out["result"].(map[string]any)["id"].(string)
	auth := map[string]string{"Authorization": "Bearer " + repoBearer}

	for name, c := range map[string]struct {
		tool   string
		body   any
		header map[string]string
		status int
		code   string
	}{
		"no token":            {"attempt_status", map[string]any{"attempt": attempt}, nil, 401, "unauthenticated"},
		"garbage bearer":      {"attempt_status", map[string]any{"attempt": attempt}, map[string]string{"Authorization": "Bearer !!!"}, 401, "invalid_token"},
		"token outside scope": {"attempt_write", map[string]any{"attempt": attempt, "path": "docs/x.md", "content": "x"}, map[string]string{"Authorization": "Bearer " + bearerOf(t, narrow)}, 403, "forbidden"},
		"unknown operation":   {"no_such_tool", map[string]any{}, auth, 404, "unknown_tool"},
		"unknown attempt":     {"attempt_status", map[string]any{"attempt": "att_" + strings.Repeat("z", 52)}, auth, 404, "not_found"},
		"body not an object":  {"attempt_status", "[1,2]", auth, 400, "invalid_json"},
		"missing argument":    {"attempt_write", map[string]any{"attempt": attempt}, auth, 422, "invalid"},
		"unparseable payload": {"evidence_submit", map[string]any{"attempt": attempt, "world": strings.Repeat("ab", 32), "kind": "test-run", "outcome": "pass", "payload": map[string]any{"tests": "many"}}, auth, 422, "invalid"},
	} {
		got, body := a.post(c.tool, c.body, c.header)
		if got != c.status || errCode(body) != c.code {
			t.Errorf("%s: %d %v, want %d %s", name, got, body, c.status, c.code)
		}
	}

	// A 401 asks for credentials.
	_, _, h := a.do(http.MethodPost, "/api/v1/tools/attempt_status", map[string]any{"attempt": attempt}, nil)
	if !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate = %q", h.Get("WWW-Authenticate"))
	}

	// 409 for a state conflict: superseding an intent twice.
	_, created := a.post("intent_create", intentArgs("one", nil), auth)
	id := created["result"].(map[string]any)["id"].(string)
	if status, out = a.post("intent_supersede", withIntent(intentArgs("two", nil), id), auth); status != 200 {
		t.Fatalf("first supersede: %d %v", status, out)
	}
	if status, out = a.post("intent_supersede", withIntent(intentArgs("three", nil), id), auth); status != 409 || errCode(out) != "conflict" {
		t.Errorf("second supersede: %d %v, want 409 conflict", status, out)
	}

	// Wrong method and path.
	if status, _, _ = a.do(http.MethodGet, "/api/v1/tools/attempt_open", nil, nil); status != 405 {
		t.Errorf("GET on an operation = %d, want 405", status)
	}
	if status, _, _ = a.do(http.MethodGet, "/api/v1/nope", nil, nil); status != 404 {
		t.Errorf("unknown path = %d, want 404", status)
	}
	if status, _, _ = a.do(http.MethodPost, "/api/v1/tools/attempt_open", map[string]any{}, map[string]string{"Origin": "http://evil.example"}); status != 403 {
		t.Errorf("cross-origin = %d, want 403", status)
	}
}

func bearerOf(t *testing.T, tokenJSON json.RawMessage) string {
	t.Helper()
	token, err := identity.Decode(tokenJSON)
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Bearer(token)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func attemptCount(t *testing.T, s *Server) int {
	t.Helper()
	attempts, err := s.Graph.ListAttempts(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	return len(attempts)
}

func TestARetryWithTheSameKeyReturnsTheFirstResultAndDoesTheWorkOnce(t *testing.T) {
	s := newTestServer(t)
	a := newAPI(t, s)
	hdr := map[string]string{"Idempotency-Key": "open-1"}

	status, first := a.post("attempt_open", map[string]any{"task": "do it once"}, hdr)
	if status != 200 || first["idempotent_replay"] != false {
		t.Fatalf("first: %d %v", status, first)
	}
	status, again := a.post("attempt_open", map[string]any{"task": "do it once"}, hdr)
	if status != 200 || again["idempotent_replay"] != true {
		t.Fatalf("retry: %d %v", status, again)
	}
	if first["result"].(map[string]any)["id"] != again["result"].(map[string]any)["id"] {
		t.Fatalf("the retry returned a different attempt: %v vs %v", first["result"], again["result"])
	}
	if n := attemptCount(t, s); n != 1 {
		t.Fatalf("%d attempts exist, want 1", n)
	}

	// A new key is a new operation.
	if _, third := a.post("attempt_open", map[string]any{"task": "do it once"}, map[string]string{"Idempotency-Key": "open-2"}); third["idempotent_replay"] != false {
		t.Fatalf("a fresh key replayed: %v", third)
	}
	// Reusing the key for a different request is refused, not silently re-run.
	status, conflict := a.post("attempt_open", map[string]any{"task": "something else"}, hdr)
	if status != 409 || !strings.Contains(conflict["error"].(map[string]any)["message"].(string), "different") {
		t.Fatalf("key reuse = %d %v, want 409", status, conflict)
	}
	// The key is scoped to the tool.
	if status, _ = a.post("intent_create", intentArgs("x", nil), hdr); status != 200 {
		t.Fatalf("the same key on another tool should be independent: %d", status)
	}
}

func TestOnlySuccessesAreRemembered(t *testing.T) {
	s := newTestServer(t)
	a := newAPI(t, s)
	hdr := map[string]string{"Idempotency-Key": "write-1"}
	_, opened := a.post("attempt_open", map[string]any{"task": "x"}, nil)
	attempt := opened["result"].(map[string]any)["id"].(string)

	// A call that fails (bad base64) is not recorded...
	if status, _ := a.post("attempt_write", map[string]any{"attempt": attempt, "path": "a.go", "content": "!!!", "encoding": "base64"}, hdr); status != 400 {
		t.Fatalf("bad write = %d", status)
	}
	// ...so the corrected request, under the same key, runs.
	status, out := a.post("attempt_write", map[string]any{"attempt": attempt, "path": "a.go", "content": "ok"}, hdr)
	if status != 200 || out["idempotent_replay"] != false {
		t.Fatalf("corrected retry: %d %v", status, out)
	}
}

func TestIdempotencyKeysThroughTheMCPInterfaceAndTheirValidation(t *testing.T) {
	s := newTestServer(t)
	first := mustCall(t, s, "attempt_open", map[string]any{"task": "mcp", "idempotency_key": "k1"})
	second := mustCall(t, s, "attempt_open", map[string]any{"task": "mcp", "idempotency_key": "k1"})
	if first["id"] != second["id"] || second["_meta"] == nil || second["_meta"].(map[string]any)["idempotent_replay"] != true {
		t.Fatalf("MCP replay = %v / %v", first, second)
	}
	for name, key := range map[string]string{"empty": "", "too long": strings.Repeat("k", 129), "padded": " k ", "control": "k\x01"} {
		if _, errText := call(t, s, "attempt_open", map[string]any{"task": "x", "idempotency_key": key}); errText == "" {
			t.Errorf("%s key accepted", name)
		}
	}
	// Reads ignore the key.
	if _, errText := call(t, s, "attempt_status", map[string]any{"attempt": first["id"], "idempotency_key": "whatever"}); errText != "" {
		t.Errorf("a read with a key: %s", errText)
	}
}

func TestConcurrentDuplicatesRunOnce(t *testing.T) {
	s := newTestServer(t)
	a := newAPI(t, s)
	var wg sync.WaitGroup
	ids := make([]any, 12)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, out := a.post("attempt_open", map[string]any{"task": "race"}, map[string]string{"Idempotency-Key": "race-1"})
			if r, ok := out["result"].(map[string]any); ok {
				ids[i] = r["id"]
			}
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if id == nil || id != ids[0] {
			t.Fatalf("concurrent duplicates got different results: %v", ids)
		}
	}
	if n := attemptCount(t, s); n != 1 {
		t.Fatalf("%d attempts were created by 12 identical concurrent calls, want 1", n)
	}
}

func TestAReplayStillNeedsAValidToken(t *testing.T) {
	s, issuer := enforcingServer(t)
	list := identity.NewMemoryRevocationList()
	s.Revocation = list
	a := newAPI(t, s)
	token := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	hdr := map[string]string{"Authorization": "Bearer " + bearerOf(t, token), "Idempotency-Key": "k"}

	if status, _ := a.post("attempt_open", map[string]any{"task": "x"}, hdr); status != 200 {
		t.Fatalf("first call = %d", status)
	}
	decoded, _ := identity.Decode(token)
	list.Revoke(decoded.ID)
	if status, out := a.post("attempt_open", map[string]any{"task": "x"}, hdr); status != 401 {
		t.Fatalf("a replay with a revoked token = %d %v, want 401: the stored result must not be readable without authority", status, out)
	}
}

func TestAnIdempotentRetryWithARefreshedTokenIsStillTheSameRequest(t *testing.T) {
	s, issuer := enforcingServer(t)
	a := newAPI(t, s)
	t1 := bearerOf(t, issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent))
	t2 := bearerOf(t, issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent))
	if t1 == t2 {
		t.Fatal("tokens should differ")
	}
	_, first := a.post("attempt_open", map[string]any{"task": "x"}, map[string]string{"Authorization": "Bearer " + t1, "Idempotency-Key": "k"})
	status, again := a.post("attempt_open", map[string]any{"task": "x"}, map[string]string{"Authorization": "Bearer " + t2, "Idempotency-Key": "k"})
	if status != 200 || again["idempotent_replay"] != true || again["result"].(map[string]any)["id"] != first["result"].(map[string]any)["id"] {
		t.Fatalf("retry with a refreshed token: %d %v", status, again)
	}
}
