package mcp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// ServeAPI serves the same operations as the MCP tools as a plain JSON HTTP API
// (IF-2), for clients that are not MCP clients:
//
//	GET  /api/v1/tools           the operations, with their input schemas
//	POST /api/v1/tools/{name}    run one; the body is its arguments
//
// A bearer token in the Authorization header stands in for the capability_token
// argument, and an Idempotency-Key header for idempotency_key. Every operation
// is non-interactive, transactional (a mutation is applied whole or not at all)
// and, given an idempotency key, safe to retry. Errors carry a status that says
// what kind of failure it was and a JSON body that says which.
//
// This is the same code path as /mcp and the stdio transport: nothing here can
// do what a tool cannot (§5.5: no feature outside the API).
func (s *Server) ServeAPI(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
			writeAPIError(w, http.StatusForbidden, "cross_origin", "cross-origin requests are not accepted")
			return
		}
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch {
	case rest == "tools" && r.Method == http.MethodGet:
		s.apiListTools(w)
	case strings.HasPrefix(rest, "tools/") && r.Method == http.MethodPost:
		s.apiCall(w, r, strings.TrimPrefix(rest, "tools/"))
	case rest == "tools" || strings.HasPrefix(rest, "tools/"):
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET /api/v1/tools lists operations; POST /api/v1/tools/{name} runs one")
	default:
		writeAPIError(w, http.StatusNotFound, "not_found", "no such API path")
	}
}

func (s *Server) apiListTools(w http.ResponseWriter) {
	names := make([]string, 0, len(s.tools))
	for name := range s.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	tools := make([]map[string]any, 0, len(names))
	for _, name := range names {
		t := s.tools[name]
		tools = append(tools, map[string]any{"name": name, "description": t.description, "mutating": mutatingTools[name], "input_schema": t.inputSchema})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

func (s *Server) apiCall(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := s.tools[name]; !ok {
		writeAPIError(w, http.StatusNotFound, "unknown_tool", "no operation named "+name)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHTTPBody))
	if err != nil {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "too_large", "request too large or unreadable")
		return
	}
	args := map[string]json.RawMessage{}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err = json.Unmarshal(body, &args); err != nil || args == nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_json", "the body must be a JSON object holding the operation's arguments")
			return
		}
	}
	if _, has := args["capability_token"]; !has {
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			token, perr := identity.ParseBearer(bearer)
			if perr != nil {
				writeAPIError(w, http.StatusUnauthorized, "invalid_token", perr.Error())
				return
			}
			encoded, _ := json.Marshal(token)
			args["capability_token"] = encoded
		}
	}
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if _, has := args["idempotency_key"]; !has {
			encoded, _ := json.Marshal(key)
			args["idempotency_key"] = encoded
		}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	result, err := s.invoke(r.Context(), name, raw)
	if err != nil {
		status, code := Classify(err)
		writeAPIError(w, status, code, err.Error())
		return
	}
	replay := false
	if m, ok := result.(map[string]any); ok {
		if meta, ok := m["_meta"].(map[string]any); ok {
			replay, _ = meta["idempotent_replay"].(bool)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "idempotent_replay": replay})
}

// Classify maps a failure to an HTTP status and a stable error code.
func Classify(err error) (int, string) {
	switch {
	case errors.Is(err, ErrTokenRequired), errors.Is(err, identity.ErrTokenExpired), errors.Is(err, identity.ErrTokenRevoked),
		errors.Is(err, identity.ErrTokenAltered), errors.Is(err, identity.ErrRootNotHuman):
		return http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, identity.ErrScopeDenied), errors.Is(err, identity.ErrOperationDenied), errors.Is(err, identity.ErrIntentMismatch),
		errors.Is(err, identity.ErrPrincipalMismatch), errors.Is(err, graph.ErrNotAuthor), errors.Is(err, graph.ErrScopeViolation),
		errors.Is(err, identity.ErrWidening), errors.Is(err, identity.ErrNotDelegable), errors.Is(err, identity.ErrSpendCeiling):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrUnknownTool), errors.Is(err, storage.ErrNotFound), errors.Is(err, graph.ErrUnknownIntent),
		errors.Is(err, graph.ErrUnknownEvidence), errors.Is(err, graph.ErrUnknownOperation), errors.Is(err, graph.ErrUnknownWorld):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, graph.ErrImmutable), errors.Is(err, graph.ErrAlreadySuperseded),
		errors.Is(err, graph.ErrEvidenceSuperseded), errors.Is(err, graph.ErrInactiveAttempt), errors.Is(err, graph.ErrIntentClosed),
		errors.Is(err, graph.ErrNotUndoable), errors.Is(err, graph.ErrNotSupersedable):
		return http.StatusConflict, "conflict"
	}
	var rpc *rpcError
	if errors.As(err, &rpc) && rpc.code == ErrCodeInvalidParams {
		return http.StatusBadRequest, "invalid_request"
	}
	if errors.Is(err, graph.ErrInvalidParams) || errors.Is(err, graph.ErrPayloadInvalid) || errors.Is(err, graph.ErrUnknownKind) || errors.Is(err, graph.ErrCycle) {
		return http.StatusUnprocessableEntity, "invalid"
	}
	return http.StatusInternalServerError, "internal"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="meiosis"`)
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}
