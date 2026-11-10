package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	backend, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return NewServer(graph.NewStore(backend), "agent:impl-3", keys.PrivateKey)
}

func TestHandleIntentCreateReturnsSignedIntent(t *testing.T) {
	s := newTestServer(t)
	args := `{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it",
		"acceptance":[{"text":"tests pass"}],"scope":{"allow":["pkg/**"],"mode":"enforce"}}`

	result, err := handleIntentCreate(context.Background(), s, json.RawMessage(args))
	if err != nil {
		t.Fatalf("handleIntentCreate() error = %v", err)
	}
	intent, ok := result.(specv1.Intent)
	if !ok {
		t.Fatalf("handleIntentCreate() returned %T, want specv1.Intent", result)
	}
	if err := intent.Validate(); err != nil {
		t.Fatalf("returned Intent.Validate() error = %v", err)
	}
	if intent.CreatedBy != s.Principal {
		t.Fatalf("CreatedBy = %q, want %q (server's own principal)", intent.CreatedBy, s.Principal)
	}
}

func TestHandleIntentCheckPathReflectsScope(t *testing.T) {
	s := newTestServer(t)
	createArgs := `{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it",
		"acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"deny":["internal/auth/secrets/**"],"mode":"enforce"}}`
	created, err := handleIntentCreate(context.Background(), s, json.RawMessage(createArgs))
	if err != nil {
		t.Fatalf("handleIntentCreate() error = %v", err)
	}
	id := created.(specv1.Intent).ID

	allowedResult, err := handleIntentCheckPath(context.Background(), s, json.RawMessage(`{"intent":"`+id+`","path":"internal/auth/handler.go"}`))
	if err != nil {
		t.Fatalf("handleIntentCheckPath() error = %v", err)
	}
	m := allowedResult.(map[string]any)
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Fatalf("intent_check_path allowed = %v, want true", m["allowed"])
	}

	deniedResult, err := handleIntentCheckPath(context.Background(), s, json.RawMessage(`{"intent":"`+id+`","path":"internal/auth/secrets/keys.pem"}`))
	if err != nil {
		t.Fatalf("handleIntentCheckPath() error = %v", err)
	}
	m = deniedResult.(map[string]any)
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("intent_check_path allowed = %v, want false for a denied path", m["allowed"])
	}
}

const testAttemptID = "att_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// putAttempt persists an open attempt by author on s's graph.
func putAttempt(t *testing.T, s *Server, author string) specv1.Attempt {
	t.Helper()
	world := specv1.MustParseWorldHash("0000000000000000000000000000000000000000000000000000000000000001")
	attempt := specv1.Attempt{
		ID: testAttemptID, Intent: "int_" + "cccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Author: author, World: world, BaseWorld: world,
		Status: specv1.AttemptStatusOpen, CreatedAt: time.Unix(1, 0).UTC(), Signature: "sig",
	}
	if err := s.Graph.PutAttempt(context.Background(), attempt); err != nil {
		t.Fatalf("PutAttempt() error = %v", err)
	}
	return attempt
}

func TestHandleEvidenceSubmitRejectsUnknownAttempt(t *testing.T) {
	s := newTestServer(t)
	args := `{"attempt":"` + testAttemptID + `","world":"0000000000000000000000000000000000000000000000000000000000000001","kind":"test-run","outcome":"pass","payload":{"passed":1}}`
	if _, err := handleEvidenceSubmit(context.Background(), s, json.RawMessage(args)); err == nil {
		t.Fatal("handleEvidenceSubmit() accepted evidence for an attempt that does not exist")
	}
}

func TestHandleEvidenceSubmitRejectsSpoofedProducer(t *testing.T) {
	s := newTestServer(t)
	putAttempt(t, s, "agent:impl-3")
	args := `{"attempt":"` + testAttemptID + `","producer":"human:reviewer","world":"0000000000000000000000000000000000000000000000000000000000000001","kind":"test-run","outcome":"pass","payload":{"passed":1}}`
	if _, err := handleEvidenceSubmit(context.Background(), s, json.RawMessage(args)); err == nil {
		t.Fatal("handleEvidenceSubmit() accepted a producer other than the authenticated principal")
	}
}

func TestHandleEvidenceSubmitMarksSelfProducedEvidenceNotIndependent(t *testing.T) {
	s := newTestServer(t)
	putAttempt(t, s, "agent:impl-3") // the daemon's own principal authored the attempt
	args := `{"attempt":"` + testAttemptID + `","world":"0000000000000000000000000000000000000000000000000000000000000001","kind":"test-run","outcome":"pass","payload":{"passed":1}}`
	result, err := handleEvidenceSubmit(context.Background(), s, json.RawMessage(args))
	if err != nil {
		t.Fatalf("handleEvidenceSubmit() error = %v", err)
	}
	if result.(specv1.Evidence).Independent {
		t.Fatal("evidence the author submitted about its own attempt must not be independent")
	}
}

func TestHandleEvidenceSubmitDefaultsProducerToServerPrincipal(t *testing.T) {
	s := newTestServer(t)
	putAttempt(t, s, "agent:someone-else")
	args := `{"attempt":"att_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"world":"0000000000000000000000000000000000000000000000000000000000000001",
		"kind":"test-run","outcome":"pass","payload":{"passed":1}}`

	result, err := handleEvidenceSubmit(context.Background(), s, json.RawMessage(args))
	if err != nil {
		t.Fatalf("handleEvidenceSubmit() error = %v", err)
	}
	evidence, ok := result.(specv1.Evidence)
	if !ok {
		t.Fatalf("handleEvidenceSubmit() returned %T, want specv1.Evidence", result)
	}
	if evidence.Producer != s.Principal {
		t.Fatalf("Producer = %q, want %q (server's own principal)", evidence.Producer, s.Principal)
	}
}

func TestServerAnswersPing(t *testing.T) {
	s := newTestServer(t)
	line := []byte(`{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	resp := s.handleLine(context.Background(), line)
	if resp == nil || resp.Error != nil {
		t.Fatalf("ping response = %+v, want a result with no error", resp)
	}
	m, ok := resp.Result.(map[string]any)
	if !ok || len(m) != 0 {
		t.Fatalf("ping result = %v, want empty object", resp.Result)
	}
}

func TestToolsListIncludesValidInputSchemas(t *testing.T) {
	s := newTestServer(t)
	listed := s.handleToolsList().(map[string]any)
	tools := listed["tools"].([]map[string]any)
	if len(tools) != 18 {
		t.Fatalf("tools/list returned %d tools, want 18", len(tools))
	}
	for _, tool := range tools {
		name := tool["name"]
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok {
			t.Fatalf("tool %v inputSchema missing or not an object (%v)", name, tool["inputSchema"])
		}
		if schema["type"] != "object" {
			t.Fatalf("tool %v inputSchema type = %v, want object", name, schema["type"])
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("tool %v inputSchema.properties missing", name)
		}
		if _, ok := props["capability_token"]; !ok {
			t.Fatalf("tool %v inputSchema must declare capability_token", name)
		}
		if _, err := json.Marshal(schema); err != nil {
			t.Fatalf("tool %v inputSchema not JSON-marshalable: %v", name, err)
		}
	}
}

func TestHandleIntentCreateRejectsInvalidArgs(t *testing.T) {
	s := newTestServer(t)
	if _, err := handleIntentCreate(context.Background(), s, json.RawMessage(`{"repo":`)); err == nil {
		t.Fatal("handleIntentCreate() expected error for malformed JSON")
	}
}

func TestHandleIntentCheckPathRejectsUnknownIntent(t *testing.T) {
	s := newTestServer(t)
	unknownID := "int_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := handleIntentCheckPath(context.Background(), s, json.RawMessage(`{"intent":"`+unknownID+`","path":"x"}`)); err == nil {
		t.Fatal("handleIntentCheckPath() expected error for an intent that was never created")
	}
}
