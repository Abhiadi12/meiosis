// Package mcp implements the MCP daemon's JSON-RPC 2.0 surface (issue #16):
// a minimal "initialize" / "tools/list" / "tools/call" handshake exposing
// intent_create, intent_check_path and evidence_submit as MCP tools, over
// any io.Reader/io.Writer transport. No external MCP SDK is used — the
// protocol surface needed here is small enough to hand-roll, matching the
// rest of the codebase's dependency-conscious style.
package mcp

import "encoding/json"

// Request is a JSON-RPC 2.0 request object. A missing ID marks it as a
// notification, per the JSON-RPC 2.0 spec: notifications get no Response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response object.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
}

// ResponseError is a JSON-RPC 2.0 error object.
type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification#error_object).
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
)

// rpcError carries a specific JSON-RPC error code, as opposed to a plain Go
// error which is reported as ErrCodeInternal.
type rpcError struct {
	code    int
	message string
	// cause, when set, is the underlying error. It lets the HTTP API pick a
	// status code by what went wrong (an expired token, a scope refusal)
	// instead of by parsing the message.
	cause error
}

func (e *rpcError) Error() string { return e.message }
func (e *rpcError) Unwrap() error { return e.cause }
