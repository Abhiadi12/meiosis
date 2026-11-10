package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/mindfire-test/meiosis/internal/evidence"
	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/scope"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
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
	s.tools = map[string]tool{
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
		"evidence_submit": {
			description: "Submit a signed evidence record (e.g. a test run's outcome) bound to a world hash.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt":   {"type": "string", "description": "attempt ID the evidence is bound to"},
					"producer":  {"type": "string", "description": "optional; must equal the authenticated principal"},
					"world":     {"type": "string", "description": "world hash the evidence was produced against"},
					"kind":      {"type": "string", "description": "a built-in kind (test-run, coverage, type-check, static-analysis, benchmark, mutation, security-scan, replay-match, human-review) or a registered custom kind (x-NAME)"},
					"outcome":   {"type": "string", "enum": ["pass", "fail", "inconclusive"]},
					"payload":   {"type": "object"},
					"footprint": {"type": "array", "items": {"type": "string"}},
					"supersedes": {"type": "string", "description": "ID of an earlier record of yours on this attempt that this one corrects"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "world", "kind", "outcome", "payload", "capability_token"]
			}`),
			handler: handleEvidenceSubmit,
		},
		"evidence_ingest": {
			description: "Turn a report your tools already produced (JUnit XML, go test -json, SARIF, Cobertura, LCOV, CycloneDX JSON) into signed evidence. The outcome comes from the report, not from you. Bound to the attempt's current world unless you name one, so commit first. Evidence you produce about your own attempt is marked not independent.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt":           {"type": "string"},
					"report":            {"type": "string", "description": "the report's text"},
					"format":            {"type": "string", "enum": ["gotest", "junit", "sarif", "cobertura", "lcov", "cyclonedx"], "description": "omit to detect from the content"},
					"kind":              {"type": "string", "description": "only for SARIF: static-analysis (default), security-scan or type-check"},
					"min_line_coverage": {"type": "number", "description": "coverage reports only: percent of lines required to pass; without it coverage is recorded as inconclusive"},
					"world":             {"type": "string", "description": "64-hex world hash; default: the attempt's current world"},
					"footprint":         {"type": "array", "items": {"type": "string"}},
					"supersedes":        {"type": "string", "description": "ID of an earlier record of yours on this attempt that this one corrects"},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["attempt", "report", "capability_token"]
			}`),
			handler: handleEvidenceIngest,
		},
		"evidence_query": {
			description: "Query the evidence recorded on attempts, with each record's current standing: counted (fresh and not superseded), stale (bound to a world the attempt has moved past) or superseded. A token bound to one intent sees only that intent's evidence.",
			inputSchema: toolInputSchema(`{
				"type": "object",
				"properties": {
					"attempt":     {"type": "string"},
					"kind":        {"type": "string"},
					"outcome":     {"type": "string", "enum": ["pass", "fail", "inconclusive"]},
					"producer":    {"type": "string"},
					"world":       {"type": "string", "description": "a world hash or a prefix of one"},
					"independent": {"type": "boolean"},
					"standing":    {"type": "string", "enum": ["counted", "stale", "superseded"]},
					` + mcpCapabilityTokenProperty + `
				},
				"required": ["capability_token"]
			}`),
			handler: handleEvidenceQuery,
		},
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

// pinArg is a context pin as an agent supplies it: either a ready digest or the
// content to hash.
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

type evidenceSubmitArgs struct {
	Attempt    string                 `json:"attempt"`
	Producer   string                 `json:"producer,omitempty"`
	World      string                 `json:"world"`
	Kind       specv1.EvidenceKind    `json:"kind"`
	Outcome    specv1.EvidenceOutcome `json:"outcome"`
	Payload    json.RawMessage        `json:"payload"`
	Footprint  []string               `json:"footprint,omitempty"`
	Supersedes string                 `json:"supersedes,omitempty"`
}

// authorizeEvidence verifies the call's capability token and that it may act on
// the attempt's intent. Evidence with no footprint touches no specific path, so
// only the token itself is verified; evidence with one authorizes each path it
// claims to have touched.
func authorizeEvidence(ctx context.Context, s *Server, raw json.RawMessage, tool, attemptID string, footprint []string) (specv1.CapabilityToken, specv1.Attempt, error) {
	var (
		token specv1.CapabilityToken
		err   error
	)
	if len(footprint) == 0 {
		if token, err = s.requireCapabilityToken(raw, ""); err != nil {
			return token, specv1.Attempt{}, err
		}
	}
	for _, path := range footprint {
		if token, err = s.requireCapabilityToken(raw, path); err != nil {
			return token, specv1.Attempt{}, err
		}
	}
	attempt, err := s.Graph.GetAttempt(ctx, attemptID)
	if err != nil {
		return token, specv1.Attempt{}, fmt.Errorf("%s: attempt %q: %w", tool, attemptID, err)
	}
	return token, attempt, s.checkIntent(token, attempt.Intent)
}

func handleEvidenceSubmit(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args evidenceSubmitArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "evidence_submit: " + err.Error()}
	}
	world, err := specv1.ParseWorldHash(args.World)
	if err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "evidence_submit: " + err.Error()}
	}
	token, attempt, err := authorizeEvidence(ctx, s, raw, "evidence_submit", args.Attempt, args.Footprint)
	if err != nil {
		return nil, err
	}

	// The producer is the authenticated principal this daemon signs as. A
	// caller cannot name someone else: that would let an agent attribute its
	// own evidence to an independent party (FR-4.4). Third-party and human
	// evidence is submitted by a daemon running as that principal.
	if args.Producer != "" && args.Producer != s.Principal {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: fmt.Sprintf("evidence_submit: producer %q does not match the authenticated principal %q", args.Producer, s.Principal)}
	}

	evidence, err := s.Graph.SubmitEvidence(ctx, graph.SubmitEvidenceParams{
		Attempt:    args.Attempt,
		Producer:   s.Principal,
		World:      world,
		Kind:       args.Kind,
		Outcome:    args.Outcome,
		Payload:    args.Payload,
		Footprint:  args.Footprint,
		Supersedes: args.Supersedes,
	}, s.Key)
	if err != nil {
		return nil, fmt.Errorf("evidence_submit: %w", err)
	}
	if err = s.recordAuthority(ctx, "evidence_submit", token, evidence.ID, attempt.ID, attempt.Intent, ""); err != nil {
		return nil, err
	}
	return evidence, nil
}

type evidenceIngestArgs struct {
	Attempt         string              `json:"attempt"`
	Report          string              `json:"report"`
	Format          string              `json:"format,omitempty"`
	Kind            specv1.EvidenceKind `json:"kind,omitempty"`
	MinLineCoverage *float64            `json:"min_line_coverage,omitempty"`
	World           string              `json:"world,omitempty"`
	Footprint       []string            `json:"footprint,omitempty"`
	Supersedes      string              `json:"supersedes,omitempty"`
}

func handleEvidenceIngest(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args evidenceIngestArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "evidence_ingest: " + err.Error()}
	}
	token, attempt, err := authorizeEvidence(ctx, s, raw, "evidence_ingest", args.Attempt, args.Footprint)
	if err != nil {
		return nil, err
	}

	// The report is bound to an explicit world: the one named, or else the
	// attempt's current committed world, which is echoed back in the result.
	world := attempt.World
	if args.World != "" {
		if world, err = specv1.ParseWorldHash(args.World); err != nil {
			return nil, &rpcError{code: ErrCodeInvalidParams, message: "evidence_ingest: world: " + err.Error()}
		}
	}
	var format evidence.Format
	if args.Format != "" {
		if format, err = evidence.ParseFormat(args.Format); err != nil {
			return nil, &rpcError{code: ErrCodeInvalidParams, message: "evidence_ingest: " + err.Error()}
		}
	}

	record, parsed, err := evidence.Ingest(ctx, s.Graph, evidence.IngestParams{
		Attempt: args.Attempt, Producer: s.Principal, World: world, Format: format,
		Options:   evidence.Options{Kind: args.Kind, MinLineCoverage: args.MinLineCoverage},
		Footprint: args.Footprint, Supersedes: args.Supersedes,
	}, s.Key, []byte(args.Report))
	if err != nil {
		return nil, fmt.Errorf("evidence_ingest: %w", err)
	}
	if err = s.recordAuthority(ctx, "evidence_ingest", token, record.ID, attempt.ID, attempt.Intent, ""); err != nil {
		return nil, err
	}
	return map[string]any{
		"evidence": record,
		"format":   parsed.Format,
		"world":    world.String(),
		"fresh":    world == attempt.World,
	}, nil
}

// authorizeAttempt verifies the call's capability token (against path, when
// non-empty), loads the attempt and checks the token may act on its intent.
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
