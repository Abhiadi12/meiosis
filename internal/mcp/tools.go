package mcp

import (
	"encoding/json"
	"maps"
)

// mcpCapabilityTokenProperty is the JSON Schema fragment listing the
// capability_token field. The daemon requires it on every tool call while
// enforcement is on, so it is declared as required in each tool schema. It
// accepts both an embedded object (the daemon's preferred form, per
// AGENTS.md) and a serialized JSON string: agents routinely stringify the
// token, and letting those calls reach the daemon yields a clear corrective
// error instead of a client-side schema rejection that aborts the agent turn.
const mcpCapabilityTokenProperty = `"capability_token":{"description":"capability token granting this call (see .agents/meiosis-capability.json)","type":["object","string"]}`

// toolInputSchema parses an authored JSON Schema string. These literals are
// written by hand at compile time and must stay valid JSON, so a parse
// failure panics rather than silently serving a null schema.
func toolInputSchema(s string) map[string]any {
	var schema map[string]any
	if err := json.Unmarshal([]byte(s), &schema); err != nil {
		panic("mcp: invalid tool input schema: " + err.Error())
	}
	return schema
}

func (s *Server) registerTools() {
	s.tools = map[string]tool{}
	for _, group := range []map[string]tool{intentTools(), attemptTools(), evidenceTools(), workspaceTools(), authorityTools()} {
		maps.Copy(s.tools, group)
	}
}
