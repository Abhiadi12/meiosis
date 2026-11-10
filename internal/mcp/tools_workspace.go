package mcp

// workspaceTools returns the workspace_* tools; their handlers are in workspace.go.
func workspaceTools() map[string]tool {
	return map[string]tool{
		"workspace_fork": {
			description: "Fork an attempt's workspace into a new attempt on the same intent, owned by you. It starts with the source's files; afterwards the two evolve independently. Nothing is copied, so it costs the same however large the workspace is.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt": {"type": "string", "description": "the attempt to fork"},
					"idempotency_key": {"type": "string"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "capability_token"]
			}`),
			handler: handleWorkspaceFork,
		},
		"workspace_diff": {
			description: "Show what an attempt's workspace changes: against its base world, or against another attempt. Lists added, modified and deleted paths with digests and sizes; with unified set, includes a unified diff of each text file.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt": {"type": "string"},
					"against": {"type": "string", "description": "another attempt to compare with; default: this attempt's base world"},
					"path":    {"type": "string", "description": "only paths matching this glob"},
					"unified": {"type": "boolean", "description": "include unified diffs of text files"},
					"max_files": {"type": "integer", "minimum": 1, "description": "default 200"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "capability_token"]
			}`),
			handler: handleWorkspaceDiff,
		},
		"workspace_oplog": {
			description: "List an attempt's operation log, newest first: every write, delete, commit, fork and undo, each signed.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt": {"type": "string"},
					"limit":   {"type": "integer", "minimum": 1, "description": "default 50"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "capability_token"]
			}`),
			handler: handleWorkspaceOplog,
		},
		"workspace_undo": {
			description: "Undo an operation in your attempt's workspace without erasing history: the undo is itself a logged operation, and undoing it redoes. By default the latest operation. Undoing a write or delete puts the path back as it was; undoing a commit restores the exact earlier world hash, so evidence bound to it counts again.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt":   {"type": "string"},
					"operation": {"type": "string", "description": "the operation to undo; default: the latest"},
					"idempotency_key": {"type": "string"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "capability_token"]
			}`),
			handler: handleWorkspaceUndo,
		},
	}
}
