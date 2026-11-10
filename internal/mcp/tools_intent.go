package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/scope"
)

// intentTools returns the intent_* tools.
func intentTools() map[string]tool {
	return map[string]tool{
		"intent_create": {
			description: "Declare a new intent (goal, acceptance criteria, scope) and receive a signed Intent.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"repo":       {"type": "string", "description": "repository this intent applies to"},
					"title":      {"type": "string"},
					"goal":       {"type": "string"},
					"acceptance": {"type": "array", "items": {"type": "object", "properties": {"text": {"type": "string"}, "check": {"type": "object"}}, "required": ["text"]}},
					"scope":      {"type": "object", "properties": {"allow": {"type": "array", "items": {"type": "string"}}, "deny": {"type": "array", "items": {"type": "string"}}, "mode": {"type": "string", "enum": ["enforce", "warn"]}}, "required": ["allow", "mode"]},
					"non_goals":   {"type": "array", "items": {"type": "string"}},
					"parent":      {"type": "string", "description": "optional parent intent ID"},
					"depends_on":  {"type": "array", "items": {"type": "string"}, "description": "intent IDs this intent depends on"},
					"context_pins": {"type": "array", "items": {"type": "object", "properties": {"ref": {"type": "string", "description": "path, URL or issue id of the document consumed"}, "kind": {"type": "string", "enum": ["spec", "adr", "issue", "design", "convention"]}, "digest": {"type": "string", "description": "64-hex BLAKE3 digest of the content as consumed"}, "content": {"type": "string", "description": "alternative to digest: the content, which the server hashes"}}, "required": ["ref"]}},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["repo", "title", "goal", "acceptance", "scope", "capability_token"]
			}`),
			handler: handleIntentCreate,
		},
		"intent_get": {
			description: "Get one intent with its current lifecycle state (status, and the successor if it was superseded).",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"intent": {"type": "string"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["intent", "capability_token"]
			}`),
			handler: handleIntentGet,
		},
		"intent_list": {
			description: "List intents with their current state, oldest first. Superseded intents are omitted unless include_superseded is set. A token bound to one intent sees only that intent.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"include_superseded": {"type": "boolean"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["capability_token"]
			}`),
			handler: handleIntentList,
		},
		"intent_supersede": {
			description: "Replace an intent with a successor. Intents are immutable, so the old one is left as it was, records the successor, and accepts no new attempts. Takes the same fields as intent_create.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"intent":     {"type": "string", "description": "the intent being superseded"},
					"repo":       {"type": "string"},
					"title":      {"type": "string"},
					"goal":       {"type": "string"},
					"acceptance": {"type": "array", "items": {"type": "object", "properties": {"text": {"type": "string"}, "check": {"type": "object"}}, "required": ["text"]}},
					"scope":      {"type": "object", "properties": {"allow": {"type": "array", "items": {"type": "string"}}, "deny": {"type": "array", "items": {"type": "string"}}, "mode": {"type": "string", "enum": ["enforce", "warn"]}}, "required": ["allow", "mode"]},
					"non_goals":   {"type": "array", "items": {"type": "string"}},
					"parent":      {"type": "string", "description": "optional parent intent ID"},
					"depends_on":  {"type": "array", "items": {"type": "string"}, "description": "intent IDs this intent depends on"},
					"context_pins": {"type": "array", "items": {"type": "object", "properties": {"ref": {"type": "string", "description": "path, URL or issue id of the document consumed"}, "kind": {"type": "string", "enum": ["spec", "adr", "issue", "design", "convention"]}, "digest": {"type": "string", "description": "64-hex BLAKE3 digest of the content as consumed"}, "content": {"type": "string", "description": "alternative to digest: the content, which the server hashes"}}, "required": ["ref"]}},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["intent", "repo", "title", "goal", "acceptance", "scope", "capability_token"]
			}`),
			handler: handleIntentSupersede,
		},
		"intent_check_path": {
			description: "Check whether a path is allowed under an existing intent's declared scope.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"intent": {"type": "string", "description": "intent ID returned by intent_create"},
					"path":   {"type": "string", "description": "repo-relative path to check against the intent's scope"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["intent", "path", "capability_token"]
			}`),
			handler: handleIntentCheckPath,
		},
	}
}

type pinArg struct {
	Ref     string `json:"ref"`
	Kind    string `json:"kind,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Content string `json:"content,omitempty"`
}

type intentCreateArgs struct {
	Repo        string             `json:"repo"`
	Title       string             `json:"title"`
	Goal        string             `json:"goal"`
	Acceptance  []specv1.Criterion `json:"acceptance"`
	Scope       specv1.Scope       `json:"scope"`
	NonGoals    []string           `json:"non_goals,omitempty"`
	Parent      string             `json:"parent,omitempty"`
	DependsOn   []string           `json:"depends_on,omitempty"`
	ContextPins []pinArg           `json:"context_pins,omitempty"`
}

// params converts the arguments into graph parameters, hashing any pin given
// as content.
func (a intentCreateArgs) params(createdBy string) (graph.CreateIntentParams, error) {
	pins := make([]specv1.ContextPin, 0, len(a.ContextPins))
	for _, p := range a.ContextPins {
		kind := specv1.ContextPinKind(p.Kind)
		if kind == "" {
			kind = specv1.ContextPinKindSpec
		}
		switch {
		case p.Digest != "" && p.Content != "":
			return graph.CreateIntentParams{}, fmt.Errorf("pin %q: give a digest or content, not both", p.Ref)
		case p.Digest != "":
			pins = append(pins, specv1.ContextPin{Ref: p.Ref, Digest: p.Digest, Kind: kind})
		default:
			pin, err := graph.NewContextPin(p.Ref, kind, []byte(p.Content))
			if err != nil {
				return graph.CreateIntentParams{}, err
			}
			pins = append(pins, pin)
		}
	}
	if len(pins) == 0 {
		pins = nil
	}
	return graph.CreateIntentParams{
		Repo: a.Repo, Title: a.Title, Goal: a.Goal, Acceptance: a.Acceptance, NonGoals: a.NonGoals,
		Scope: a.Scope, ContextPins: pins, Parent: a.Parent, DependsOn: a.DependsOn, CreatedBy: createdBy,
	}, nil
}

func handleIntentCreate(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args intentCreateArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_create: " + err.Error()}
	}
	token, err := s.requireRepoToken(raw)
	if err != nil {
		return nil, err
	}
	params, err := args.params(s.Principal)
	if err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_create: " + err.Error()}
	}
	intent, err := s.Graph.CreateIntent(ctx, params, s.Key)
	if err != nil {
		return nil, fmt.Errorf("intent_create: %w", err)
	}
	if err = s.recordAuthority(ctx, "intent_create", token, intent.ID, "", intent.ID, ""); err != nil {
		return nil, err
	}
	return intent, nil
}

type intentGetArgs struct {
	Intent string `json:"intent"`
}

func handleIntentGet(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args intentGetArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_get: " + err.Error()}
	}
	token, err := s.requireCapabilityToken(raw, "")
	if err != nil {
		return nil, err
	}
	if err = s.checkIntent(token, args.Intent); err != nil {
		return nil, err
	}
	view, err := s.Graph.GetIntentView(ctx, args.Intent)
	if err != nil {
		return nil, fmt.Errorf("intent_get: %w", err)
	}
	return view, nil
}

type intentListArgs struct {
	IncludeSuperseded bool `json:"include_superseded,omitempty"`
}

func handleIntentList(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args intentListArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_list: " + err.Error()}
	}
	token, err := s.requireCapabilityToken(raw, "")
	if err != nil {
		return nil, err
	}
	views, err := s.Graph.ListIntentViews(ctx, args.IncludeSuperseded)
	if err != nil {
		return nil, fmt.Errorf("intent_list: %w", err)
	}
	// A token bound to one intent may only see that intent.
	if s.IssuerKey != nil && token.Intent != specv1.CapabilityTokenAnyIntent {
		visible := views[:0]
		for _, v := range views {
			if v.ID == token.Intent {
				visible = append(visible, v)
			}
		}
		views = visible
	}
	return map[string]any{"intents": views}, nil
}

type intentSupersedeArgs struct {
	Intent string `json:"intent"`
	intentCreateArgs
}

func handleIntentSupersede(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args intentSupersedeArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_supersede: " + err.Error()}
	}
	// Creating the successor is creating an intent: repository-level authority.
	token, err := s.requireRepoToken(raw)
	if err != nil {
		return nil, err
	}
	params, err := args.params(s.Principal)
	if err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_supersede: " + err.Error()}
	}
	successor, err := s.Graph.SupersedeIntent(ctx, args.Intent, params, s.Key)
	if err != nil {
		return nil, fmt.Errorf("intent_supersede: %w", err)
	}
	if err = s.recordAuthority(ctx, "intent_supersede", token, successor.ID, "", successor.ID, ""); err != nil {
		return nil, err
	}
	return map[string]any{"superseded": args.Intent, "successor": successor}, nil
}

type intentCheckPathArgs struct {
	Intent string `json:"intent"`
	Path   string `json:"path"`
}

func handleIntentCheckPath(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args intentCheckPathArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "intent_check_path: " + err.Error()}
	}
	token, err := s.requireCapabilityToken(raw, args.Path)
	if err != nil {
		return nil, err
	}
	if err = s.checkIntent(token, args.Intent); err != nil {
		return nil, err
	}

	intent, err := s.Graph.GetIntent(ctx, args.Intent)
	if err != nil {
		return nil, fmt.Errorf("intent_check_path: %w", err)
	}
	allowed, err := scope.New(intent.Scope).IsPathAllowed(args.Path)
	if err != nil {
		return nil, fmt.Errorf("intent_check_path: %w", err)
	}
	return map[string]any{
		"path":    args.Path,
		"allowed": allowed,
		"mode":    intent.Scope.Mode,
	}, nil
}
