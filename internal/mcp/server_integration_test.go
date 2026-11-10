package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/mcp"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// rpcClient drives an mcp.Server over an in-memory pipe, the same way an
// agent's MCP client would drive meiosisd over its stdin/stdout — this is
// the "agent-to-daemon MCP communication over stdio" integration test #16
// asks for; it exercises the exact Serve loop meiosisd's stdio mode uses,
// just over an io.Pipe instead of a real process's stdio.
type rpcClient struct {
	toServer   io.WriteCloser
	fromServer *bufio.Scanner
}

func newRPCClient(t *testing.T) *rpcClient {
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
	server := mcp.NewServer(graph.NewStore(backend), "agent:impl-3", keys.PrivateKey)

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

func (c *rpcClient) call(t *testing.T, id int, method string, params string) map[string]any {
	t.Helper()
	req := `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"` + method + `"`
	if params != "" {
		req += `,"params":` + params
	}
	req += "}\n"
	if _, err := io.WriteString(c.toServer, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if !c.fromServer.Scan() {
		t.Fatalf("no response for %s: %v", method, c.fromServer.Err())
	}
	var resp map[string]any
	if err := json.Unmarshal(c.fromServer.Bytes(), &resp); err != nil {
		t.Fatalf("decode response for %s: %v", method, err)
	}
	if errObj, ok := resp["error"]; ok && errObj != nil {
		t.Fatalf("%s returned RPC error: %v", method, errObj)
	}
	return resp
}

func TestServerServesAgentSessionOverStdio(t *testing.T) {
	client := newRPCClient(t)

	initResp := client.call(t, 1, "initialize", "")
	result, ok := initResp["result"].(map[string]any)
	if !ok || result["serverInfo"] == nil {
		t.Fatalf("initialize result = %#v, want a serverInfo field", initResp["result"])
	}

	listResp := client.call(t, 2, "tools/list", "")
	listResult := listResp["result"].(map[string]any)
	tools, _ := listResult["tools"].([]any)
	if len(tools) != 18 {
		t.Fatalf("tools/list returned %d tools, want 18", len(tools))
	}

	createResp := client.call(t, 3, "tools/call", `{"name":"intent_create","arguments":{"repo":"github.com/example/repo","title":"Add feature","goal":"Implement it","acceptance":[{"text":"tests pass"}],"scope":{"allow":["internal/auth/**"],"mode":"enforce"}}}`)
	createResult := createResp["result"].(map[string]any)
	if createResult["isError"] == true {
		t.Fatalf("intent_create tool call failed: %v", createResult)
	}
	structured := createResult["structuredContent"].(map[string]any)
	intentID, _ := structured["id"].(string)
	if intentID == "" {
		t.Fatalf("intent_create returned no intent id: %v", structured)
	}
	if structured["signature"] == "" {
		t.Fatal("intent_create returned an unsigned intent")
	}

	checkResp := client.call(t, 4, "tools/call", `{"name":"intent_check_path","arguments":{"intent":"`+intentID+`","path":"internal/auth/handler.go"}}`)
	checkResult := checkResp["result"].(map[string]any)
	checkStructured := checkResult["structuredContent"].(map[string]any)
	if allowed, _ := checkStructured["allowed"].(bool); !allowed {
		t.Fatalf("intent_check_path allowed = %v, want true", checkStructured["allowed"])
	}
}
