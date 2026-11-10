package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// DelegateParams describes the authority being passed to a sub-principal. Any
// field left at its zero value is inherited from the parent token.
type DelegateParams struct {
	// Principal is the sub-principal receiving the capability.
	Principal string
	// HolderKey is the sub-principal's public key. Without it the delegated
	// token cannot be delegated further.
	HolderKey ed25519.PublicKey

	Intent             string
	Scope              *specv1.Scope
	Operations         []string
	SpendCeilingMicros *int64
	TTL                time.Duration // zero means the shorter of DefaultTTL and the parent's remaining life
	IssuedAt           time.Time     // zero means now
}

// Delegate issues a token from parent's holder to a sub-principal, signed with
// the holder's key (FR-1.5). The result may hold only a strict subset of the
// parent's authority on every axis a token carries: widening is refused here,
// at issuance, with ErrWidening, and is checked again whenever the token is
// verified, so a delegator that signs a wider token by hand gains nothing.
//
// Delegate does not verify the parent's own chain or revocation; Verify does
// that when the delegated token is used.
func Delegate(parent specv1.CapabilityToken, p DelegateParams, delegatorKey ed25519.PrivateKey) (specv1.CapabilityToken, error) {
	if parent.HolderKey == "" {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: it was issued without a holder key", ErrNotDelegable)
	}
	holder, err := base64.StdEncoding.DecodeString(parent.HolderKey)
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: its holder key is malformed", ErrNotDelegable)
	}
	if len(delegatorKey) != ed25519.PrivateKeySize || !ed25519.PublicKey(holder).Equal(delegatorKey.Public()) {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: only the holder of a token may delegate it", ErrNotDelegable)
	}
	if parent.Operations != nil && !unrestricted(parent.Operations) && !hasOperation(parent.Operations, "capability_delegate") {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: its operations do not include capability_delegate", ErrNotDelegable)
	}
	if p.Principal == "" || p.Principal == parent.Principal {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: a delegation needs a sub-principal other than %s", ErrInvalidParams, parent.Principal)
	}
	if parent.Depth() >= specv1.MaxDelegationDepth {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: delegations may be at most %d deep", ErrWidening, specv1.MaxDelegationDepth)
	}

	issuedAt := p.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
		if remaining := parent.ExpiresAt.Sub(issuedAt); remaining < ttl {
			ttl = remaining
		}
	}
	if ttl <= 0 {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: the parent token has expired", ErrTokenExpired)
	}

	id, err := newTokenID()
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("identity: generate token id: %w", err)
	}
	child := specv1.CapabilityToken{
		ID:                 id,
		Principal:          p.Principal,
		IssuedBy:           parent.Principal,
		Intent:             parent.Intent,
		Scope:              cloneScope(parent.Scope),
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(ttl),
		Operations:         append([]string(nil), parent.Operations...),
		SpendCeilingMicros: parent.SpendCeilingMicros,
		Parent:             &parent,
	}
	if p.Intent != "" {
		child.Intent = p.Intent
	}
	if p.Scope != nil {
		child.Scope = cloneScope(*p.Scope)
	}
	if p.Operations != nil {
		child.Operations = append([]string(nil), p.Operations...)
	}
	if p.SpendCeilingMicros != nil {
		v := *p.SpendCeilingMicros
		child.SpendCeilingMicros = &v
	}
	if len(p.HolderKey) > 0 {
		child.HolderKey = base64.StdEncoding.EncodeToString(p.HolderKey)
	}

	if err = narrower(parent, child); err != nil {
		return specv1.CapabilityToken{}, err
	}
	signature, err := crypto.Sign(child, delegatorKey)
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("identity: sign delegated token: %w", err)
	}
	child.Signature = signature
	if err = child.Validate(); err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return child, nil
}

func cloneScope(s specv1.Scope) specv1.Scope {
	return specv1.Scope{Allow: append([]string(nil), s.Allow...), Deny: append([]string(nil), s.Deny...), Mode: s.Mode}
}

func hasOperation(ops []string, op string) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}

// CheckOperation reports whether token permits operation op (FR-1.4). A token
// with no operation list permits everything. Because a delegated token may
// only narrow its parent's operations, checking the token itself is enough.
func CheckOperation(token specv1.CapabilityToken, op string) error {
	if unrestricted(token.Operations) || hasOperation(token.Operations, op) {
		return nil
	}
	return fmt.Errorf("%w: %s (token allows %v)", ErrOperationDenied, op, token.Operations)
}

// SpendLimit is one spend ceiling in a delegation chain.
type SpendLimit struct {
	TokenID       string
	CeilingMicros int64
}

// SpendLimits returns every spend ceiling in token's chain. Cost reported under
// a delegated token is charged against all of them, so a sub-agent cannot spend
// past what its delegator was given.
func SpendLimits(token specv1.CapabilityToken) []SpendLimit {
	var limits []SpendLimit
	for _, t := range token.Chain() {
		if t.SpendCeilingMicros != nil {
			limits = append(limits, SpendLimit{TokenID: t.ID, CeilingMicros: *t.SpendCeilingMicros})
		}
	}
	return limits
}

// ChainLink is one step of a delegation chain, as shown to a human.
type ChainLink struct {
	TokenID   string `json:"token_id"`
	Principal string `json:"principal"` // who holds this link's authority
	IssuedBy  string `json:"issued_by"` // who granted it
}

// Origin returns the principal at the root of the chain: the originating
// human (FR-1.6).
func Origin(token specv1.CapabilityToken) string {
	chain := token.Chain()
	return chain[len(chain)-1].IssuedBy
}

// Links lists the chain from the holder of token back to the originating human.
func Links(token specv1.CapabilityToken) []ChainLink {
	chain := token.Chain()
	links := make([]ChainLink, 0, len(chain))
	for _, t := range chain {
		links = append(links, ChainLink{TokenID: t.ID, Principal: t.Principal, IssuedBy: t.IssuedBy})
	}
	return links
}
