package mcp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mindfire-test/meiosis/internal/identity"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type capabilityDelegateArgs struct {
	Principal          string        `json:"principal"`
	HolderKey          string        `json:"holder_key,omitempty"`
	Scope              *specv1.Scope `json:"scope,omitempty"`
	Operations         []string      `json:"operations,omitempty"`
	SpendCeilingMicros *int64        `json:"spend_ceiling_micros,omitempty"`
	Intent             string        `json:"intent,omitempty"`
	TTLSeconds         int64         `json:"ttl_seconds,omitempty"`
}

// handleCapabilityDelegate lets an agent hand a strict subset of its authority
// to a sub-agent (FR-1.5). The token presented with the call is the parent; the
// delegated token is signed with this daemon's key, which must be the key the
// parent token names as its holder.
func handleCapabilityDelegate(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args capabilityDelegateArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "capability_delegate: " + err.Error()}
	}
	if s.IssuerKey == nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "capability_delegate: delegation needs capability enforcement to be on"}
	}
	parent, err := s.requireCapabilityToken(raw, "")
	if err != nil {
		return nil, err
	}

	var holder ed25519.PublicKey
	if args.HolderKey != "" {
		key, decErr := base64.StdEncoding.DecodeString(args.HolderKey)
		if decErr != nil || len(key) != ed25519.PublicKeySize {
			return nil, &rpcError{code: ErrCodeInvalidParams, message: "capability_delegate: holder_key must be a base64 Ed25519 public key"}
		}
		holder = key
	}
	params := identity.DelegateParams{
		Principal: args.Principal, HolderKey: holder, Intent: args.Intent, Scope: args.Scope,
		Operations: args.Operations, SpendCeilingMicros: args.SpendCeilingMicros,
		TTL: time.Duration(args.TTLSeconds) * time.Second,
	}
	child, err := identity.Delegate(parent, params, s.Key)
	if err != nil {
		return nil, fmt.Errorf("capability_delegate: %w", err)
	}
	if err = s.recordAuthority(ctx, "capability_delegate", parent, child.ID, "", "", ""); err != nil {
		return nil, err
	}
	return map[string]any{
		"token":      child,
		"origin":     identity.Origin(child),
		"depth":      child.Depth(),
		"expires_at": child.ExpiresAt,
	}, nil
}

type authorityChainArgs struct {
	Ref string `json:"ref,omitempty"`
}

// chainEntry is one recorded write with the chain behind it.
type chainEntry struct {
	Record   string               `json:"record"`
	Op       string               `json:"op"`
	At       time.Time            `json:"at"`
	Object   string               `json:"object,omitempty"`
	Attempt  string               `json:"attempt,omitempty"`
	Intent   string               `json:"intent,omitempty"`
	Path     string               `json:"path,omitempty"`
	Actor    string               `json:"actor"`
	Origin   string               `json:"origin"`
	Chain    []identity.ChainLink `json:"chain"`
	Verified bool                 `json:"verified"`
	Problem  string               `json:"problem,omitempty"`
}

func handleAuthorityChain(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var args authorityChainArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, &rpcError{code: ErrCodeInvalidParams, message: "authority_chain: " + err.Error()}
	}
	if _, err := s.requireRepoToken(raw); err != nil {
		return nil, err
	}
	return s.authorityChain(ctx, args.Ref)
}

// authorityChain lists the recorded writes concerning ref, each with its
// delegation chain and whether that chain verifies against the trusted issuer
// as of the moment of the write (so a token that has since expired still
// verifies for the write it authorised).
func (s *Server) authorityChain(ctx context.Context, ref string) (any, error) {
	records, err := s.Graph.ListAuthority(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("authority_chain: %w", err)
	}
	entries := make([]chainEntry, 0, len(records))
	for _, r := range records {
		e := chainEntry{
			Record: r.ID, Op: r.Op, At: r.At, Object: r.Object, Attempt: r.Attempt, Intent: r.Intent, Path: r.Path,
			Actor: r.Principal, Origin: identity.Origin(r.Token), Chain: identity.Links(r.Token),
		}
		if verr := identity.Verify(r.Token, s.IssuerKey, nil, r.At); verr != nil {
			e.Problem = verr.Error()
		} else {
			e.Verified = true
		}
		entries = append(entries, e)
	}
	return map[string]any{"writes": entries}, nil
}
