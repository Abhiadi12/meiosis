package mcp

// authorityTools returns capability_delegate and authority_chain; their handlers are in delegation.go.
func authorityTools() map[string]tool {
	return map[string]tool{
		"capability_delegate": {
			description: "Delegate part of your authority to a sub-agent. You hand over a token that holds a strict subset of your own: paths, operations, spend ceiling and lifetime can only narrow, never widen. The sub-agent runs with its own key; pass its public key as holder_key. The result is a token for the sub-agent to present, carrying the chain back to the human who started it.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"principal":            {"type": "string", "description": "the sub-agent, e.g. agent:tests-1"},
					"holder_key":           {"type": "string", "description": "the sub-agent's Ed25519 public key (base64). Without it the sub-agent cannot delegate further"},
					"scope":                {"type": "object", "properties": {"allow": {"type": "array", "items": {"type": "string"}}, "deny": {"type": "array", "items": {"type": "string"}}, "mode": {"type": "string", "enum": ["enforce", "warn"]}}, "required": ["allow", "mode"], "description": "omit to pass on your whole scope"},
					"operations":           {"type": "array", "items": {"type": "string"}, "description": "tools the sub-agent may call; omit to pass on all of yours"},
					"spend_ceiling_micros": {"type": "integer", "minimum": 0, "description": "most the sub-agent may spend; counts against yours too"},
					"intent":               {"type": "string", "description": "bind the sub-agent to one intent"},
					"ttl_seconds":          {"type": "integer", "minimum": 1, "description": "lifetime; never longer than yours"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["principal", "capability_token"]
			}`),
			handler: handleCapabilityDelegate,
		},
		"authority_chain": {
			description: "Show who authorised the writes concerning an intent, attempt or object: every recorded write with the delegation chain back to the originating human, and whether that chain still verifies. Needs a repository-level token.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"ref": {"type": "string", "description": "an intent, attempt, evidence or other object ID; omit for every write"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["capability_token"]
			}`),
			handler: handleAuthorityChain,
		},
	}
}
