package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/mcp"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// newEnforcingRPCClient is newRPCClient (server_integration_test.go) plus
// capability-token enforcement turned on, signed by issuer.
func newEnforcingRPCClient(t *testing.T, issuer crypto.KeyPair) *rpcClient {
	t.Helper()
	backend, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	agentKeys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	server := mcp.NewServer(graph.NewStore(backend), "agent:impl-3", agentKeys.PrivateKey)
	server.IssuerKey = issuer.PublicKey

	clientToServerR, clientToServerW := io.Pipe()
	serverToClientR, serverToClientW := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, clientToServerR, serverToClientW) }()
	t.Cleanup(func() {
		_ = clientToServerW.Close()
		select {
		case serveErr := <-done:
			_ = serveErr // the connection was closed on purpose; its error is not a failure
		case <-time.After(time.Second):
		}
	})

	return &rpcClient{toServer: clientToServerW, fromServer: bufio.NewScanner(serverToClientR)}
}

func TestServerRejectsToolCallsWithoutCapabilityToken(t *testing.T) {
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	client := newEnforcingRPCClient(t, issuer)
	client.call(t, 1, "initialize", "")

	resp := client.call(t, 2, "tools/call", `{"name":"intent_create","arguments":{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it","acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"mode":"enforce"}}}`)
	result := resp["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("intent_create without a capability token = %v, want isError", result)
	}
}

func TestServerAcceptsToolCallsWithValidCapabilityToken(t *testing.T) {
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	token, err := identity.Issue(identity.IssueParams{
		Principal: "agent:impl-3",
		Intent:    "int_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedBy:  "human:lakin",
		Scope:     specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
	}, issuer.PrivateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	encoded, err := identity.Encode(token)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	client := newEnforcingRPCClient(t, issuer)
	client.call(t, 1, "initialize", "")

	resp := client.call(t, 2, "tools/call", `{"name":"intent_create","arguments":{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it","acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"mode":"enforce"},"capability_token":`+string(encoded)+`}}`)
	result := resp["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("intent_create with a valid capability token failed: %v", result)
	}
}

func TestServerAcceptsStringifiedCapabilityToken(t *testing.T) {
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	token, err := identity.Issue(identity.IssueParams{
		Principal: "agent:impl-3",
		Intent:    "int_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedBy:  "human:lakin",
		Scope:     specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
	}, issuer.PrivateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	encoded, err := identity.Encode(token)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	// A client may serialize the token as a JSON string instead of embedding
	// the object; the daemon must accept that form.
	quoted, err := json.Marshal(string(encoded))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	client := newEnforcingRPCClient(t, issuer)
	client.call(t, 1, "initialize", "")

	resp := client.call(t, 2, "tools/call", `{"name":"intent_create","arguments":{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it","acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"mode":"enforce"},"capability_token":`+string(quoted)+`}}`)
	result := resp["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("intent_create with a stringified capability token failed: %v", result)
	}
}

func TestServerRejectsCapabilityTokenOutsideItsScope(t *testing.T) {
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	token, err := identity.Issue(identity.IssueParams{
		Principal: "agent:impl-3",
		Intent:    "int_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedBy:  "human:lakin",
		Scope:     specv1.Scope{Allow: []string{"docs/**"}, Mode: specv1.ScopeModeEnforce},
	}, issuer.PrivateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	encoded, err := identity.Encode(token)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	client := newEnforcingRPCClient(t, issuer)
	client.call(t, 1, "initialize", "")

	createResp := client.call(t, 2, "tools/call", `{"name":"intent_create","arguments":{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it","acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"mode":"enforce"},"capability_token":`+string(encoded)+`}}`)
	createResult := createResp["result"].(map[string]any)
	structured, _ := createResult["structuredContent"].(map[string]any)
	intentID, _ := structured["id"].(string)
	if intentID == "" {
		t.Fatalf("intent_create with a valid token failed: %v", createResult)
	}

	checkResp := client.call(t, 3, "tools/call", `{"name":"intent_check_path","arguments":{"intent":"`+intentID+`","path":"internal/auth/handler.go","capability_token":`+string(encoded)+`}}`)
	checkResult := checkResp["result"].(map[string]any)
	if checkResult["isError"] != true {
		t.Fatalf("intent_check_path outside the token's own scope = %v, want isError", checkResult)
	}
}

func TestServerRejectsExpiredCapabilityToken(t *testing.T) {
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	token, err := identity.Issue(identity.IssueParams{
		Principal: "agent:impl-3",
		Intent:    "int_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedBy:  "human:lakin",
		Scope:     specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		TTL:       time.Hour,
	}, issuer.PrivateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	encoded, err := identity.Encode(token)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	client := newEnforcingRPCClient(t, issuer)
	client.call(t, 1, "initialize", "")

	resp := client.call(t, 2, "tools/call", `{"name":"intent_create","arguments":{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it","acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"mode":"enforce"},"capability_token":`+string(encoded)+`}}`)
	result := resp["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("intent_create with an expired capability token = %v, want isError", result)
	}
}
