package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
)

// attemptTools returns the attempt_* tools.
func attemptTools() map[string]tool {
	return map[string]tool{
		"attempt_open": {
			description: "Open an attempt. Give either an existing intent ID, or just your task description and an intent is derived for you. Returns the attempt; write files to it with attempt_write, then attempt_commit.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"intent":     {"type": "string", "description": "intent ID the attempt implements"},
					"task":       {"type": "string", "description": "alternative to intent: your task description. An intent is derived from it for you, so you never have to author one"},
					"repo":       {"type": "string", "description": "repository, used only when deriving an intent from task; default \".\""},
					"base_world": {"type": "string", "description": "optional 64-hex world hash to start from; default: the empty world"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["capability_token"]
			}`),
			handler: handleAttemptOpen,
		},
		"attempt_write": {
			description: "Write (or delete) one file in an attempt. The path is checked against the intent's scope at write time: in enforce mode an out-of-scope path is rejected and nothing is stored; in warn mode it is stored and recorded as a scope violation.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt":  {"type": "string"},
					"path":     {"type": "string", "description": "repo-relative, slash-separated path"},
					"content":  {"type": "string", "description": "file content (omit when deleting)"},
					"encoding": {"type": "string", "enum": ["utf8", "base64"], "description": "how content is encoded; default utf8"},
					"delete":   {"type": "boolean", "description": "delete the path instead of writing it"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "path", "capability_token"]
			}`),
			handler: handleAttemptWrite,
		},
		"attempt_commit": {
			description: "Snapshot an attempt into a world hash and record signed provenance (model, tools, prompt digest, usage). The prompt itself is never stored, only its digest.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt":     {"type": "string"},
					"model":       {"type": "string", "description": "model identifier, e.g. claude-opus-5"},
					"model_ver":   {"type": "string"},
					"tools":       {"type": "array", "items": {"type": "string"}, "description": "tools the agent used"},
					"prompt":      {"type": "string", "description": "the prompt; only its BLAKE3 digest is stored"},
					"prompt_hash": {"type": "string", "description": "alternative to prompt: a 64-hex BLAKE3 digest"},
					"seed":        {"type": "integer"},
					"params":      {"type": "object", "additionalProperties": {"type": "string"}},
					"tokens_in":   {"type": "integer"},
					"tokens_out":  {"type": "integer"},
					"cost_micros": {"type": "integer"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "capability_token"]
			}`),
			handler: handleAttemptCommit,
		},
		"attempt_status": {
			description: "Show an attempt: its world, scope violations, provenance, workspace files and evidence with freshness.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt": {"type": "string"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "capability_token"]
			}`),
			handler: handleAttemptStatus,
		},
	}
}

func authorizeAttempt(ctx context.Context, s *Server, raw json.RawMessage, attemptID, path, tool string) (specv1.Attempt, specv1.CapabilityToken, error) {
	token, err := s.requireCapabilityToken(raw, path)
	if err != nil {
		return specv1.Attempt{}, token, err
	}
	attempt, err := s.Graph.GetAttempt(ctx, attemptID)
	if err != nil {
		return specv1.Attempt{}, token, fmt.Errorf("%s: attempt %q: %w", tool, attemptID, err)
	}
	if err := s.checkIntent(token, attempt.Intent); err != nil {
		return specv1.Attempt{}, token, err
	}
	return attempt, token, nil
}

type attemptOpenArgs struct {
	Intent    string `json:"intent,omitempty"`
	Task      string `json:"task,omitempty"`
	Repo      string `json:"repo,omitempty"`
	BaseWorld string `json:"base_world,omitempty"`
}

// attemptOpened is the attempt plus whether its intent was derived for the
// caller from a task description.
type attemptOpened struct {
	specv1.Attempt
	IntentTitle   string `json:"intent_title"`
	DerivedIntent bool   `json:"derived_intent"`
}

func handleAttemptOpen(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args attemptOpenArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_open: " + err.Error()}
	}
	if (args.Intent == "") == (args.Task == "") {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_open: give exactly one of intent (an existing intent ID) or task (a description to derive an intent from)"}
	}
	token, err := s.requireCapabilityToken(raw, "")
	if err != nil {
		return nil, err
	}

	intentID, title, derived := args.Intent, "", false
	if args.Task != "" {
		// Deriving an intent creates one, which takes repository-level authority.
		if s.IssuerKey != nil && token.Intent != specv1.CapabilityTokenAnyIntent {
			return nil, &rpcError{code: ErrCodeInvalidParams, message: "capability token is bound to " + token.Intent + " and cannot derive new intents; pass that intent explicitly"}
		}
		repo := args.Repo
		if repo == "" {
			repo = "."
		}
		// The derived intent's scope is the authority the agent already holds.
		scope := specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeWarn}
		if s.IssuerKey != nil {
			scope = token.Scope
		}
		intent, created, deriveErr := s.Graph.DeriveIntent(ctx, graph.DeriveIntentParams{Repo: repo, Task: args.Task, Scope: scope, CreatedBy: s.Principal}, s.Key)
		if deriveErr != nil {
			return nil, fmt.Errorf("attempt_open: derive intent: %w", deriveErr)
		}
		intentID, title, derived = intent.ID, intent.Title, created
	} else if err = s.checkIntent(token, args.Intent); err != nil {
		return nil, err
	}

	var base specv1.WorldHash
	if args.BaseWorld != "" {
		if base, err = specv1.ParseWorldHash(args.BaseWorld); err != nil {
			return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_open: base_world: " + err.Error()}
		}
	}
	attempt, err := s.Graph.OpenAttempt(ctx, graph.OpenAttemptParams{Intent: intentID, Author: s.Principal, BaseWorld: base}, s.Key)
	if err != nil {
		return nil, fmt.Errorf("attempt_open: %w", err)
	}
	if err = s.recordAuthority(ctx, "attempt_open", token, attempt.ID, attempt.ID, attempt.Intent, ""); err != nil {
		return nil, err
	}
	if title == "" {
		if view, vErr := s.Graph.GetIntentView(ctx, intentID); vErr == nil {
			title = view.Title
		}
	}
	return attemptOpened{Attempt: attempt, IntentTitle: title, DerivedIntent: derived}, nil
}

type attemptWriteArgs struct {
	Attempt  string `json:"attempt"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Encoding string `json:"encoding,omitempty"`
	Delete   bool   `json:"delete,omitempty"`
}

func handleAttemptWrite(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args attemptWriteArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_write: " + err.Error()}
	}
	attemptBefore, token, err := authorizeAttempt(ctx, s, raw, args.Attempt, args.Path, "attempt_write")
	if err != nil {
		return nil, err
	}

	var content []byte
	if !args.Delete {
		switch args.Encoding {
		case "", "utf8":
			content = []byte(args.Content)
		case "base64":
			decoded, decErr := base64.StdEncoding.DecodeString(args.Content)
			if decErr != nil {
				return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_write: content is not valid base64: " + decErr.Error()}
			}
			content = decoded
		default:
			return nil, &rpcError{code: ErrCodeInvalidParams, message: fmt.Sprintf("attempt_write: unknown encoding %q", args.Encoding)}
		}
	}

	result, err := s.Graph.WriteFile(ctx, graph.WriteParams{
		Attempt: args.Attempt, Author: s.Principal, Path: args.Path, Content: content, Delete: args.Delete,
	}, s.Key)
	if err != nil {
		return nil, fmt.Errorf("attempt_write: %w", err)
	}
	if err = s.recordAuthority(ctx, "attempt_write", token, args.Attempt, args.Attempt, attemptBefore.Intent, args.Path); err != nil {
		return nil, err
	}
	violations := result.Attempt.ScopeViolations
	if violations == nil {
		violations = []specv1.ScopeViolation{}
	}
	out := map[string]any{
		"attempt":          result.Attempt.ID,
		"path":             args.Path,
		"deleted":          args.Delete,
		"accepted":         true,
		"scope_violations": violations,
	}
	if result.Violation != nil {
		out["warning"] = fmt.Sprintf("path %q is outside the intent's scope (%s); recorded as a scope violation (mode: warn)", result.Violation.Path, result.Violation.Reason)
	}
	return out, nil
}

type attemptCommitArgs struct {
	Attempt    string            `json:"attempt"`
	Model      string            `json:"model,omitempty"`
	ModelVer   string            `json:"model_ver,omitempty"`
	Tools      []string          `json:"tools,omitempty"`
	Prompt     string            `json:"prompt,omitempty"`
	PromptHash string            `json:"prompt_hash,omitempty"`
	Seed       *int64            `json:"seed,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	TokensIn   int64             `json:"tokens_in,omitempty"`
	TokensOut  int64             `json:"tokens_out,omitempty"`
	CostMicros int64             `json:"cost_micros,omitempty"`
}

func handleAttemptCommit(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args attemptCommitArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_commit: " + err.Error()}
	}
	attemptBefore, token, err := authorizeAttempt(ctx, s, raw, args.Attempt, "", "attempt_commit")
	if err != nil {
		return nil, err
	}
	// Cost reported at commit is charged against every spend ceiling in the
	// token's delegation chain (FR-1.4).
	var limits []graph.SpendLimit
	if s.IssuerKey != nil {
		for _, l := range identity.SpendLimits(token) {
			limits = append(limits, graph.SpendLimit{TokenID: l.TokenID, CeilingMicros: l.CeilingMicros})
		}
	}
	result, err := s.Graph.CommitAttempt(ctx, graph.CommitParams{
		Attempt: args.Attempt, Author: s.Principal,
		Model: args.Model, ModelVer: args.ModelVer, Tools: args.Tools,
		Prompt: args.Prompt, PromptHash: args.PromptHash, Seed: args.Seed, Params: args.Params,
		TokensIn: args.TokensIn, TokensOut: args.TokensOut, CostMicros: args.CostMicros, SpendLimits: limits,
	}, s.Key)
	if err != nil {
		return nil, fmt.Errorf("attempt_commit: %w", err)
	}
	if err = s.recordAuthority(ctx, "attempt_commit", token, args.Attempt, args.Attempt, attemptBefore.Intent, ""); err != nil {
		return nil, err
	}
	return map[string]any{
		"attempt":          result.Attempt.ID,
		"world":            result.Attempt.World.String(),
		"base_world":       result.Attempt.BaseWorld.String(),
		"files":            result.Files,
		"changed":          result.Changed,
		"scope_violations": result.Attempt.ScopeViolations,
		"attestation":      result.Attestation,
	}, nil
}

type attemptStatusArgs struct {
	Attempt string `json:"attempt"`
}

func handleAttemptStatus(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args attemptStatusArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "attempt_status: " + err.Error()}
	}
	attempt, _, err := authorizeAttempt(ctx, s, raw, args.Attempt, "", "attempt_status")
	if err != nil {
		return nil, err
	}
	report, err := graph.BuildAttemptReport(ctx, s.Graph, attempt)
	if err != nil {
		return nil, fmt.Errorf("attempt_status: %w", err)
	}
	return report, nil
}
