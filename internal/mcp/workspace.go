package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/textdiff"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type evidenceQueryArgs struct {
	Attempt     string `json:"attempt,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Outcome     string `json:"outcome,omitempty"`
	Producer    string `json:"producer,omitempty"`
	World       string `json:"world,omitempty"`
	Independent *bool  `json:"independent,omitempty"`
	Standing    string `json:"standing,omitempty"`
}

func handleEvidenceQuery(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args evidenceQueryArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "evidence_query: " + err.Error()}
	}
	token, err := s.requireCapabilityToken(raw, "")
	if err != nil {
		return nil, err
	}
	filter := graph.EvidenceFilter{
		Attempt: args.Attempt, Kind: args.Kind, Outcome: args.Outcome, Producer: args.Producer,
		World: args.World, Independent: args.Independent, Standing: args.Standing,
	}
	// A token bound to an intent sees only that intent's evidence, and may not
	// ask about another's attempt by name.
	if s.IssuerKey != nil && token.Intent != specv1.CapabilityTokenAnyIntent {
		filter.Intent = token.Intent
	}
	if args.Attempt != "" {
		attempt, getErr := s.Graph.GetAttempt(ctx, args.Attempt)
		if getErr != nil {
			return nil, fmt.Errorf("evidence_query: attempt %q: %w", args.Attempt, getErr)
		}
		if err = s.checkIntent(token, attempt.Intent); err != nil {
			return nil, err
		}
	}
	views, err := s.Graph.QueryEvidence(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("evidence_query: %w", err)
	}
	return map[string]any{"evidence": views, "count": len(views)}, nil
}

type workspaceForkArgs struct {
	Attempt string `json:"attempt"`
}

func handleWorkspaceFork(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args workspaceForkArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "workspace_fork: " + err.Error()}
	}
	source, token, err := authorizeAttempt(ctx, s, raw, args.Attempt, "", "workspace_fork")
	if err != nil {
		return nil, err
	}
	forked, err := s.Graph.ForkAttempt(ctx, graph.ForkParams{Source: source.ID, Author: s.Principal}, s.Key)
	if err != nil {
		return nil, fmt.Errorf("workspace_fork: %w", err)
	}
	if err = s.recordAuthority(ctx, "workspace_fork", token, forked.ID, forked.ID, forked.Intent, ""); err != nil {
		return nil, err
	}
	return forked, nil
}

type workspaceDiffArgs struct {
	Attempt  string `json:"attempt"`
	Against  string `json:"against,omitempty"`
	Path     string `json:"path,omitempty"`
	Unified  bool   `json:"unified,omitempty"`
	MaxFiles int    `json:"max_files,omitempty"`
}

// Limits that keep one diff response bounded.
const (
	defaultDiffFiles = 200
	maxDiffBytes     = 512 << 10
)

type diffEntry struct {
	graph.FileChange
	Diff string `json:"diff,omitempty"`
}

func handleWorkspaceDiff(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args workspaceDiffArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "workspace_diff: " + err.Error()}
	}
	attempt, token, err := authorizeAttempt(ctx, s, raw, args.Attempt, "", "workspace_diff")
	if err != nil {
		return nil, err
	}
	if args.Against != "" {
		other, getErr := s.Graph.GetAttempt(ctx, args.Against)
		if getErr != nil {
			return nil, fmt.Errorf("workspace_diff: attempt %q: %w", args.Against, getErr)
		}
		if err = s.checkIntent(token, other.Intent); err != nil {
			return nil, err
		}
	}
	if args.Path != "" {
		if _, matchErr := doublestar.Match(args.Path, "x"); matchErr != nil {
			return nil, &rpcError{code: ErrCodeInvalidParams, message: "workspace_diff: path is not a valid glob: " + matchErr.Error()}
		}
	}
	limit := args.MaxFiles
	if limit <= 0 {
		limit = defaultDiffFiles
	}

	changes, err := s.Graph.Changes(ctx, attempt.ID, args.Against)
	if err != nil {
		return nil, fmt.Errorf("workspace_diff: %w", err)
	}
	var entries []diffEntry
	counts := map[string]int{}
	truncated, budget := false, maxDiffBytes
	for _, c := range changes {
		if args.Path != "" {
			if ok, _ := doublestar.Match(args.Path, c.Path); !ok {
				continue
			}
		}
		counts[c.Status]++
		if len(entries) >= limit {
			truncated = true
			continue
		}
		e := diffEntry{FileChange: c}
		if args.Unified {
			var before, after []byte
			if c.Before != "" {
				before, _ = s.Graph.Blob(ctx, c.Before)
			}
			if c.After != "" {
				after, _ = s.Graph.Blob(ctx, c.After)
			}
			d := textdiff.Unified(path.Clean(c.Path), before, after, 3)
			if len(d) > budget {
				d, truncated = "(diff omitted: the response size limit was reached)\n", true
			}
			budget -= len(d)
			e.Diff = d
		}
		entries = append(entries, e)
	}
	against := "base world " + attempt.BaseWorld.String()
	if args.Against != "" {
		against = "attempt " + args.Against
	}
	return map[string]any{
		"attempt": attempt.ID, "against": against, "changes": nonNilEntries(entries),
		"counts": counts, "truncated": truncated,
	}, nil
}

func nonNilEntries(e []diffEntry) []diffEntry {
	if e == nil {
		return []diffEntry{}
	}
	return e
}

type workspaceOplogArgs struct {
	Attempt string `json:"attempt"`
	Limit   int    `json:"limit,omitempty"`
}

func handleWorkspaceOplog(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args workspaceOplogArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "workspace_oplog: " + err.Error()}
	}
	attempt, _, err := authorizeAttempt(ctx, s, raw, args.Attempt, "", "workspace_oplog")
	if err != nil {
		return nil, err
	}
	ops, err := s.Graph.ListOperations(ctx, attempt.ID)
	if err != nil {
		return nil, fmt.Errorf("workspace_oplog: %w", err)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 50
	}
	total := len(ops)
	if len(ops) > limit {
		ops = ops[:limit]
	}
	return map[string]any{"attempt": attempt.ID, "operations": ops, "total": total, "world": attempt.World.String()}, nil
}

type workspaceUndoArgs struct {
	Attempt   string `json:"attempt"`
	Operation string `json:"operation,omitempty"`
}

func handleWorkspaceUndo(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args workspaceUndoArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "workspace_undo: " + err.Error()}
	}
	attempt, token, err := authorizeAttempt(ctx, s, raw, args.Attempt, "", "workspace_undo")
	if err != nil {
		return nil, err
	}
	op, err := s.Graph.RevertOperation(ctx, graph.RevertParams{Attempt: attempt.ID, Author: s.Principal, Operation: args.Operation}, s.Key)
	if err != nil {
		return nil, fmt.Errorf("workspace_undo: %w", err)
	}
	if err = s.recordAuthority(ctx, "workspace_undo", token, op.ID, attempt.ID, attempt.Intent, op.Path); err != nil {
		return nil, err
	}
	current, err := s.Graph.GetAttempt(ctx, attempt.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"operation": op, "reverted": op.Reverts, "world": current.World.String()}, nil
}
