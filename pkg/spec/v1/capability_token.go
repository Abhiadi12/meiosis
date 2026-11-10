package v1

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"time"
)

// MaxDelegationDepth bounds how many delegations may stack on a root token.
const MaxDelegationDepth = 8

// CapabilityOperationAll is the wildcard operation: as the only entry of
// Operations it permits every operation, as does an empty list.
const CapabilityOperationAll = "*"

// CapabilityOperations are the operations a token's Operations list may name.
// Each is an agent-facing tool of the MCP surface.
var CapabilityOperations = []string{
	"intent_create", "intent_get", "intent_list", "intent_supersede", "intent_check_path",
	"attempt_open", "attempt_write", "attempt_commit", "attempt_status",
	"evidence_submit", "evidence_ingest",
	"capability_delegate", "authority_chain",
	"git_fetch", "git_push",
	"evidence_query", "workspace_fork", "workspace_diff", "workspace_oplog", "workspace_undo",
}

// IsCapabilityOperation reports whether op is a known operation name.
func IsCapabilityOperation(op string) bool {
	for _, known := range CapabilityOperations {
		if op == known {
			return true
		}
	}
	return false
}

// CapabilityTokenAnyIntent is the Intent value of a repository-level token: one
// not bound to a single intent. Such a token may create intents and act on any
// intent within its path scope. Any other Intent value binds the token to
// exactly that intent.
const CapabilityTokenAnyIntent = "int_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// CapabilityToken grants a principal a narrow, time-bounded permission to
// operate within an intent's declared scope. It is the credential a principal
// presents before a write is admitted (FR-1.3/FR-1.4); Intent.Scope is still
// enforced separately at commit time (FR-3.4).
//
// The token is signed by the issuing principal, not the holder: Principal is
// who the capability is granted to, IssuedBy is who granted it and whose key
// produced Signature. A principal can therefore never mint or widen its own
// authority — it can only be delegated a subset of what an issuer holds
// (FR-1.5).
type CapabilityToken struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	IssuedBy  string    `json:"issued_by"`
	Intent    string    `json:"intent"`
	Scope     Scope     `json:"scope"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// HolderKey is the holder's Ed25519 public key (base64), asserted by the
	// issuer. It is what lets the holder delegate: a token with no HolderKey
	// cannot be delegated. The delegation chain is then verifiable from the root
	// issuer's key alone.
	HolderKey string `json:"holder_key,omitempty"`
	// Operations restricts the token to the named operations (FR-1.4). Empty or
	// ["*"] means every operation.
	Operations []string `json:"operations,omitempty"`
	// SpendCeilingMicros caps the cost (micro-units) reported by commits made
	// under this token and anything delegated from it (FR-1.4). Absent means no
	// ceiling; zero means no spend at all.
	SpendCeilingMicros *int64 `json:"spend_ceiling_micros,omitempty"`
	// Parent is the token this one was delegated from, embedded whole so the
	// chain to the originating human travels with the token (FR-1.5, FR-1.6).
	// A root token has no Parent.
	Parent *CapabilityToken `json:"parent,omitempty"`

	Signature string `json:"signature"`
}

// Validate reports whether the token is well formed; it checks shape, not signatures or expiry (see internal/identity.Verify).
func (t CapabilityToken) Validate() error {
	return t.validate(0)
}

func (t CapabilityToken) validate(depth int) error {
	if depth > MaxDelegationDepth {
		return ErrInvalidCapabilityToken
	}
	if !validContentID(t.ID, "cap_") || !validPrincipalID(t.Principal) || !validPrincipalID(t.IssuedBy) || !validContentID(t.Intent, "int_") || t.IssuedAt.IsZero() || t.ExpiresAt.IsZero() || strings.TrimSpace(t.Signature) == "" {
		return ErrInvalidCapabilityToken
	}
	if !t.ExpiresAt.After(t.IssuedAt) {
		return ErrInvalidCapabilityToken
	}
	if t.Scope.Validate() != nil {
		return ErrInvalidCapabilityToken
	}
	if t.HolderKey != "" {
		raw, err := base64.StdEncoding.DecodeString(t.HolderKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return ErrInvalidCapabilityToken
		}
	}
	seen := map[string]bool{}
	for _, op := range t.Operations {
		if (op != CapabilityOperationAll && !IsCapabilityOperation(op)) || seen[op] {
			return ErrInvalidCapabilityToken
		}
		seen[op] = true
	}
	if t.SpendCeilingMicros != nil && *t.SpendCeilingMicros < 0 {
		return ErrInvalidCapabilityToken
	}
	if t.Parent != nil {
		if t.Parent.validate(depth+1) != nil {
			return ErrInvalidCapabilityToken
		}
	}
	return nil
}

// Depth returns how many delegations sit between t and its root token: 0 for a
// root token.
func (t CapabilityToken) Depth() int {
	n := 0
	for p := t.Parent; p != nil && n <= MaxDelegationDepth; p = p.Parent {
		n++
	}
	return n
}

// Chain returns the tokens from t up to its root, t first.
func (t CapabilityToken) Chain() []CapabilityToken {
	chain := []CapabilityToken{t}
	for p := t.Parent; p != nil && len(chain) <= MaxDelegationDepth+1; p = p.Parent {
		chain = append(chain, *p)
	}
	return chain
}

// Expired reports whether the token's validity window has passed as of now.
func (t CapabilityToken) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

// AuthorityRecord records one write together with the capability token, and so
// the whole delegation chain, it was made under (FR-1.6). It is append-only and
// signed by the principal that made the write. Given any write, the chain back
// to the originating human is the Token's chain.
type AuthorityRecord struct {
	ID        string          `json:"id"`
	Op        string          `json:"op"`
	Principal string          `json:"principal"`
	Token     CapabilityToken `json:"token"`
	Object    string          `json:"object,omitempty"`
	Attempt   string          `json:"attempt,omitempty"`
	Intent    string          `json:"intent,omitempty"`
	Path      string          `json:"path,omitempty"`
	At        time.Time       `json:"at"`
	Signature string          `json:"signature"`
}

// Validate reports whether the record is well formed; it checks shape, not signatures.
func (r AuthorityRecord) Validate() error {
	if !validContentID(r.ID, "aut_") || !IsCapabilityOperation(r.Op) || !validPrincipalID(r.Principal) || r.At.IsZero() || strings.TrimSpace(r.Signature) == "" {
		return ErrInvalidCapabilityToken
	}
	if r.Token.Validate() != nil {
		return ErrInvalidCapabilityToken
	}
	return nil
}
