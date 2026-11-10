package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// maxHTTPBody bounds one JSON-RPC request over HTTP. It is well above what
// the stdio transport's line buffer allows, since reports can be large.
const maxHTTPBody = 16 << 20

// ServeHTTP serves one JSON-RPC request per POST: the request is the body, the
// response is the reply. It is the HTTP form of the same protocol the stdio and
// socket transports speak, so everything a tool checks (capability tokens,
// scope, operations) is unchanged. A notification, which has no reply, gets 202.
//
// Calls are made as this Server's principal: it signs what it creates with its
// own key, so a token presented here must have been issued to that principal.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST a JSON-RPC request", http.StatusMethodNotAllowed)
		return
	}
	// A browser page must not be able to drive this endpoint (DNS rebinding):
	// a request that names an origin must name this server's.
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
			http.Error(w, "cross-origin requests are not accepted", http.StatusForbidden)
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHTTPBody))
	if err != nil {
		http.Error(w, "request too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		http.Error(w, "batch requests are not supported", http.StatusBadRequest)
		return
	}

	resp := s.handleLine(r.Context(), body)
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
