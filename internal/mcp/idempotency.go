package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/zeebo/blake3"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

var (
	// ErrTokenRequired is the cause of a refusal for want of a usable capability token.
	ErrTokenRequired = errors.New("a capability token is required")
	// ErrUnknownTool is the cause of a call to a tool that does not exist.
	ErrUnknownTool = errors.New("unknown tool")
	// ErrIdempotencyConflict is the cause of reusing a key for a different request.
	ErrIdempotencyConflict = errors.New("idempotency key reused with different arguments")
)

// mutatingTools are the tools that change state and so accept an idempotency
// key (IF-2). Reads do not need one.
var mutatingTools = map[string]bool{
	"intent_create": true, "intent_supersede": true,
	"attempt_open": true, "attempt_write": true, "attempt_commit": true,
	"evidence_submit": true, "evidence_ingest": true,
	"capability_delegate": true, "workspace_fork": true, "workspace_undo": true,
}

const maxIdempotencyKey = 128

// idempotencyKey extracts and validates the optional idempotency_key argument.
func idempotencyKey(args json.RawMessage) (string, error) {
	var env struct {
		Key *string `json:"idempotency_key"`
	}
	if err := json.Unmarshal(args, &env); err != nil || env.Key == nil {
		return "", nil //nolint:nilerr // not parseable, or no key: the tool handler reports any real problem
	}
	key := *env.Key
	if key == "" || len(key) > maxIdempotencyKey || strings.TrimSpace(key) != key {
		return "", &rpcError{code: ErrCodeInvalidParams, message: fmt.Sprintf("idempotency_key must be 1 to %d characters with no surrounding space", maxIdempotencyKey)}
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return "", &rpcError{code: ErrCodeInvalidParams, message: "idempotency_key must be printable ASCII"}
		}
	}
	return key, nil
}

// requestDigest identifies a request independently of the credentials sent with
// it and of the key itself: the same operation retried with a refreshed token
// is the same request.
func requestDigest(args json.RawMessage) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return "", err
	}
	delete(m, "idempotency_key")
	delete(m, "capability_token")
	canonical, err := specv1.Canonicalize(m)
	if err != nil {
		return "", err
	}
	sum := blake3.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// idempotent runs handler once per (principal, tool, key). A retry with the same
// arguments returns the original result, marked in _meta; the same key with
// different arguments is refused, since the caller clearly did not mean a retry.
// Only successes are remembered: a failed call can be retried and may succeed.
//
// The guarantee holds within one server process. Two processes sharing a
// database (the daemon and `mei serve`) do not coordinate: a retry that races
// the original in the other process can run twice.
func (s *Server) idempotent(ctx context.Context, tool, key string, args json.RawMessage, handler ToolHandler) (any, error) {
	id := idempotencyID(s.Principal, tool, key)
	digest, err := requestDigest(args)
	if err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "invalid arguments: " + err.Error()}
	}

	lock, _ := s.idemLocks.LoadOrStore(id, &sync.Mutex{})
	mu, _ := lock.(*sync.Mutex) // only *sync.Mutex values are ever stored
	mu.Lock()
	defer mu.Unlock()

	rec, found, err := s.Graph.GetIdempotent(ctx, id)
	if err != nil {
		return nil, err
	}
	if found {
		if rec.Digest != digest {
			return nil, &rpcError{
				code: ErrCodeInvalidParams, cause: ErrIdempotencyConflict,
				message: fmt.Sprintf("idempotency key %q was used for a different %s request; use a new key for a new operation", key, tool),
			}
		}
		// A replay must still be authorised: a revoked or foreign token does not
		// get to read back what a previous call returned.
		if _, authErr := s.requireCapabilityToken(args, ""); authErr != nil {
			return nil, authErr
		}
		var replay map[string]any
		if err = json.Unmarshal(rec.Result, &replay); err != nil || replay == nil {
			return nil, fmt.Errorf("stored result for idempotency key %q is unreadable", key)
		}
		replay["_meta"] = map[string]any{"idempotent_replay": true}
		return replay, nil
	}

	result, err := handler(ctx, s, args)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	// The work is done; a failure to remember it must not turn a success into an
	// error the caller would retry (and so repeat the work).
	_ = s.Graph.PutIdempotent(ctx, id, digest, encoded)
	return result, nil
}

func idempotencyID(principal, tool, key string) string {
	sum := blake3.Sum256([]byte(principal + "\x00" + tool + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

// addIdempotencySchema advertises the idempotency_key argument on every
// mutating tool.
func (s *Server) addIdempotencySchema() {
	for name := range mutatingTools {
		t, ok := s.tools[name]
		if !ok {
			continue
		}
		if props, ok := t.inputSchema["properties"].(map[string]any); ok {
			props["idempotency_key"] = map[string]any{
				"type":        "string",
				"description": "optional: a retry with the same key and arguments returns the first call's result instead of repeating it",
				"maxLength":   maxIdempotencyKey,
			}
		}
	}
}
