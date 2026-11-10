package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// call runs one tool through the full JSON-RPC path and returns its decoded
// structured result, or the tool's error text.
func call(t *testing.T, s *Server, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
	if err != nil {
		t.Fatal(err)
	}
	resp := s.handleLine(context.Background(), line)
	if resp == nil || resp.Error != nil {
		t.Fatalf("%s: rpc failure: %+v", name, resp)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] == true {
		return nil, result["content"].([]map[string]any)[0]["text"].(string)
	}
	raw, _ := json.Marshal(result["structuredContent"])
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: decode result: %v", name, err)
	}
	return out, ""
}

func declareIntent(t *testing.T, s *Server, token json.RawMessage, mode string) string {
	t.Helper()
	var tok any
	_ = json.Unmarshal(token, &tok)
	out, errText := call(t, s, "intent_create", map[string]any{
		"repo": "r", "title": "Fix auth " + mode, "goal": "g", "acceptance": []map[string]any{{"text": "ok"}},
		"scope":            map[string]any{"allow": []string{"src/**"}, "deny": []string{"src/secret/**"}, "mode": mode},
		"capability_token": tok,
	})
	if errText != "" {
		t.Fatalf("intent_create: %s", errText)
	}
	return out["id"].(string)
}

func tokenArg(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var tok any
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestExitCriterionRejectedOutOfScopeWriteAndProvenanceRecord is the M1 exit
// criterion end to end through the MCP surface with capability enforcement on:
// an agent gets an out-of-scope write rejected, and a provenance record for the
// work it did in scope.
func TestExitCriterionRejectedOutOfScopeWriteAndProvenanceRecord(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	intentID := declareIntent(t, s, repoToken, "enforce")

	opened, errText := call(t, s, "attempt_open", map[string]any{"intent": intentID, "capability_token": tokenArg(t, repoToken)})
	if errText != "" {
		t.Fatalf("attempt_open: %s", errText)
	}
	attemptID := opened["id"].(string)

	write := func(path, content string) (map[string]any, string) {
		return call(t, s, "attempt_write", map[string]any{
			"attempt": attemptID, "path": path, "content": content, "capability_token": tokenArg(t, repoToken),
		})
	}

	// 1. The out-of-scope write is rejected, with a message that explains why.
	_, errText = write("docs/notes.md", "hello")
	if !strings.Contains(errText, "docs/notes.md") || !strings.Contains(errText, "outside the scope") || !strings.Contains(errText, "no allow rule") {
		t.Fatalf("out-of-scope write error = %q, want a legible scope rejection", errText)
	}
	if _, errText = write("src/secret/k.pem", "x"); !strings.Contains(errText, `deny rule "src/secret/**"`) {
		t.Fatalf("denied-path error = %q, want the deny rule named", errText)
	}

	// 2. In-scope work is accepted and committed with provenance.
	out, errText := write("src/auth.go", "package src")
	if errText != "" || out["accepted"] != true {
		t.Fatalf("in-scope write: %v %s", out, errText)
	}
	committed, errText := call(t, s, "attempt_commit", map[string]any{
		"attempt": attemptID, "model": "claude-opus-5", "model_ver": "1", "prompt": "do the thing",
		"tokens_in": 5, "tokens_out": 7, "capability_token": tokenArg(t, repoToken),
	})
	if errText != "" {
		t.Fatalf("attempt_commit: %s", errText)
	}
	world := committed["world"].(string)
	if world == "" || world == committed["base_world"] {
		t.Fatalf("commit did not bind a new world: %v", committed)
	}

	// 3. The provenance record is queryable and the rejected paths were never stored.
	status, errText := call(t, s, "attempt_status", map[string]any{"attempt": attemptID, "capability_token": tokenArg(t, repoToken)})
	if errText != "" {
		t.Fatalf("attempt_status: %s", errText)
	}
	att, _ := status["attestation"].(map[string]any)
	if att == nil || att["model"] != "claude-opus-5" || att["agent"] != s.Principal {
		t.Fatalf("status attestation = %v, want provenance for %s", status["attestation"], s.Principal)
	}
	files, _ := status["workspace_files"].([]any)
	if len(files) != 1 || files[0] != "src/auth.go" {
		t.Fatalf("workspace_files = %v, want only the in-scope file", files)
	}
}

func TestAttemptWriteWarnModeAcceptsAndWarns(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	intentID := declareIntent(t, s, repoToken, "warn")
	opened, _ := call(t, s, "attempt_open", map[string]any{"intent": intentID, "capability_token": tokenArg(t, repoToken)})

	out, errText := call(t, s, "attempt_write", map[string]any{
		"attempt": opened["id"], "path": "docs/x.md", "content": "x", "capability_token": tokenArg(t, repoToken),
	})
	if errText != "" {
		t.Fatalf("warn-mode write rejected: %s", errText)
	}
	if out["warning"] == nil {
		t.Fatalf("result = %v, want a warning", out)
	}
	if v, _ := out["scope_violations"].([]any); len(v) != 1 {
		t.Fatalf("scope_violations = %v, want one", out["scope_violations"])
	}
}

func TestAttemptWriteChecksTokenScopeAndIntentBinding(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	intentID := declareIntent(t, s, repoToken, "enforce")
	opened, _ := call(t, s, "attempt_open", map[string]any{"intent": intentID, "capability_token": tokenArg(t, repoToken)})

	// A token narrower than the intent's scope refuses a path the intent allows.
	narrow, err := identity.Issue(identity.IssueParams{
		Principal: s.Principal, Intent: intentID, IssuedBy: "human:lakin",
		Scope: specv1.Scope{Allow: []string{"src/only/**"}, Mode: specv1.ScopeModeEnforce},
	}, issuerKeyOf(t, s, issuer))
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := identity.Encode(narrow)
	_, errText := call(t, s, "attempt_write", map[string]any{
		"attempt": opened["id"], "path": "src/other.go", "content": "x", "capability_token": tokenArg(t, enc),
	})
	if !strings.Contains(errText, "does not permit") {
		t.Fatalf("narrow token error = %q, want a token scope denial", errText)
	}

	// A token bound to a different intent is refused.
	otherIntent := issueToken(t, issuer, s.Principal, "int_"+strings.Repeat("f", 52))
	_, errText = call(t, s, "attempt_write", map[string]any{
		"attempt": opened["id"], "path": "src/a.go", "content": "x", "capability_token": tokenArg(t, otherIntent),
	})
	if !strings.Contains(errText, "different intent") {
		t.Fatalf("wrong-intent token error = %q", errText)
	}
}

func issuerKeyOf(t *testing.T, _ *Server, issuer crypto.KeyPair) []byte {
	t.Helper()
	return issuer.PrivateKey
}

func TestAttemptWriteBase64AndDelete(t *testing.T) {
	s := newTestServer(t) // enforcement off
	intent, err := s.Graph.CreateIntent(context.Background(), graph.CreateIntentParams{
		Repo: "r", Title: "t", Goal: "g", Acceptance: []specv1.Criterion{{Text: "ok"}},
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}, CreatedBy: "human:lakin",
	}, s.Key)
	if err != nil {
		t.Fatal(err)
	}
	opened, _ := call(t, s, "attempt_open", map[string]any{"intent": intent.ID})
	id := opened["id"]

	if _, errText := call(t, s, "attempt_write", map[string]any{"attempt": id, "path": "bin/blob", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255})}); errText != "" {
		t.Fatalf("base64 write: %s", errText)
	}
	if _, errText := call(t, s, "attempt_write", map[string]any{"attempt": id, "path": "bin/blob", "encoding": "base64", "content": "!!!"}); errText == "" {
		t.Fatal("invalid base64 accepted")
	}
	if _, errText := call(t, s, "attempt_write", map[string]any{"attempt": id, "path": "bin/blob", "delete": true}); errText != "" {
		t.Fatalf("delete: %s", errText)
	}
	status, _ := call(t, s, "attempt_status", map[string]any{"attempt": id})
	if del, _ := status["workspace_deletions"].([]any); len(del) != 1 {
		t.Fatalf("workspace_deletions = %v, want one", status["workspace_deletions"])
	}
}

func TestOtherPrincipalCannotWriteToAttempt(t *testing.T) {
	s := newTestServer(t)
	intent, _ := s.Graph.CreateIntent(context.Background(), graph.CreateIntentParams{
		Repo: "r", Title: "t", Goal: "g", Acceptance: []specv1.Criterion{{Text: "ok"}},
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}, CreatedBy: "human:lakin",
	}, s.Key)
	opened, _ := call(t, s, "attempt_open", map[string]any{"intent": intent.ID})

	other := newTestServer(t)
	other.Principal = "agent:intruder"
	other.Graph = s.Graph
	_, errText := call(t, other, "attempt_write", map[string]any{"attempt": opened["id"], "path": "a.go", "content": "x"})
	if !strings.Contains(errText, "only the attempt's author") {
		t.Fatalf("error = %q, want an author-only rejection", errText)
	}
}

func TestToolsListIncludesAttemptTools(t *testing.T) {
	s := newTestServer(t)
	names := map[string]bool{}
	for _, tl := range s.handleToolsList().(map[string]any)["tools"].([]map[string]any) {
		names[tl["name"].(string)] = true
	}
	for _, want := range []string{"attempt_open", "attempt_write", "attempt_commit", "attempt_status"} {
		if !names[want] {
			t.Errorf("tools/list is missing %s", want)
		}
	}
}
