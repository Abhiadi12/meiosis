package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"

	"github.com/mindfire-test/meiosis/internal/evidence"
	"github.com/mindfire-test/meiosis/internal/graph"
)

// evidenceTools returns the evidence_* tools. evidence_query is handled in workspace.go beside the other read-side tools.
func evidenceTools() map[string]tool {
	return map[string]tool{
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
	}
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
