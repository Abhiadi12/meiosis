// Package identity issues and verifies capability tokens: signed,
// time-bounded, path-scoped grants that let a principal act on an intent.
// See SRS §6.1, FR-1.3/FR-1.4.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// DefaultTTL is the default capability token lifetime. NFR-4.3 requires
// capability tokens to be short-lived, defaulting to one hour.
const DefaultTTL = time.Hour

// tokenIDEncoding mirrors the lower-case, unpadded base32 alphabet used for
// content IDs elsewhere in spec/v1. Capability token IDs are random rather
// than content-derived: two tokens issued with identical fields still need
// independent identities so one can be revoked without the other.
var tokenIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// IssueParams describes the capability being granted.
type IssueParams struct {
	Principal string        // who the token authorizes (the holder)
	Intent    string        // the intent this capability is scoped to
	Scope     specv1.Scope  // path glob constraints; Deny overrides Allow
	IssuedBy  string        // who is granting it (the issuer; signs the token)
	IssuedAt  time.Time     // zero means time.Now().UTC()
	TTL       time.Duration // zero means DefaultTTL

	// HolderKey is the holder's public key. Set it for any token the holder
	// should be able to delegate from.
	HolderKey ed25519.PublicKey
	// Operations limits the token to the named operations; empty means all.
	Operations []string
	// SpendCeilingMicros caps cost reported under the token; nil means no ceiling.
	SpendCeilingMicros *int64
}

// Issue signs a new capability token with the issuer's private key. The
// issuer, not the holder, signs the token, so a principal can never mint or
// widen its own authority — it can only be delegated a subset of what an
// issuer already holds (FR-1.5).
func Issue(params IssueParams, issuerKey ed25519.PrivateKey) (specv1.CapabilityToken, error) {
	issuedAt := params.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	ttl := params.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	id, err := newTokenID()
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("identity: generate token id: %w", err)
	}

	token := specv1.CapabilityToken{
		ID:        id,
		Principal: params.Principal,
		IssuedBy:  params.IssuedBy,
		Intent:    params.Intent,
		Scope:     params.Scope,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(ttl),

		Operations:         params.Operations,
		SpendCeilingMicros: params.SpendCeilingMicros,
	}
	if len(params.HolderKey) > 0 {
		token.HolderKey = base64.StdEncoding.EncodeToString(params.HolderKey)
	}
	signature, err := crypto.Sign(token, issuerKey)
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("identity: sign token: %w", err)
	}
	token.Signature = signature

	if err := token.Validate(); err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return token, nil
}

// Verify checks a capability token's signature, expiration and revocation
// status against the root issuer's public key. For a delegated token it checks
// the whole chain: every link must be signed by the previous link's holder,
// must not widen it, must be unexpired and unrevoked, and the chain must start
// at a human principal (FR-1.5, FR-1.6, FR-1.7). It does not check the token's
// scope against any specific path — call Authorize for that at the point a
// write is intercepted.
func Verify(token specv1.CapabilityToken, issuerKey ed25519.PublicKey, revoked RevocationChecker, now time.Time) error {
	if err := token.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrTokenAltered, err)
	}
	return verifyLink(token, issuerKey, revoked, now)
}

func verifyLink(token specv1.CapabilityToken, issuerKey ed25519.PublicKey, revoked RevocationChecker, now time.Time) error {
	signer := issuerKey
	if token.Parent == nil {
		if !strings.HasPrefix(token.IssuedBy, "human:") {
			return fmt.Errorf("%w: %s issued the root token", ErrRootNotHuman, token.IssuedBy)
		}
	} else {
		parent := *token.Parent
		if err := verifyLink(parent, issuerKey, revoked, now); err != nil {
			return err
		}
		if token.IssuedBy != parent.Principal {
			return fmt.Errorf("%w: %s delegated a token that %s holds", ErrTokenAltered, token.IssuedBy, parent.Principal)
		}
		key, err := base64.StdEncoding.DecodeString(parent.HolderKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: the parent token has no holder key to delegate from", ErrNotDelegable)
		}
		signer = ed25519.PublicKey(key)
		if err := narrower(parent, token); err != nil {
			return err
		}
	}
	ok, err := crypto.Verify(token, token.Signature, signer)
	if err != nil || !ok {
		return ErrTokenAltered
	}
	if token.Expired(now) {
		return ErrTokenExpired
	}
	if revoked != nil && revoked.IsRevoked(token.ID) {
		return ErrTokenRevoked
	}
	return nil
}

// Authorize is the single check a write path — a git push, an MCP tool call,
// a CLI mutation — should run before admitting an operation performed under a
// capability token. It is the "local interception pipeline" integration point
// named in FR-1.3: callers run this once instead of separately re-checking
// signature, expiry, revocation and scope.
//
// The scope check here duplicates the glob evaluation the dedicated scope
// engine (FR-3.4, internal/scope) also performs, against a different source
// of allow/deny rules: this checks the token's own grant, not the intent's
// declared bounds. A real write path is expected to run both.
func Authorize(token specv1.CapabilityToken, issuerKey ed25519.PublicKey, revoked RevocationChecker, path string, now time.Time) error {
	if err := Verify(token, issuerKey, revoked, now); err != nil {
		return err
	}
	allowed, err := scopeAllows(token.Scope, path)
	if err != nil {
		return fmt.Errorf("identity: evaluate scope: %w", err)
	}
	if !allowed {
		return fmt.Errorf("%w: %s", ErrScopeDenied, path)
	}
	return nil
}

func scopeAllows(scope specv1.Scope, path string) (bool, error) {
	for _, pattern := range scope.Deny {
		matched, err := doublestar.Match(pattern, path)
		if err != nil {
			return false, err
		}
		if matched {
			return false, nil
		}
	}
	for _, pattern := range scope.Allow {
		matched, err := doublestar.Match(pattern, path)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// Encode returns a capability token's canonical JSON encoding: the
// deterministic form used for storage and transmission.
func Encode(token specv1.CapabilityToken) ([]byte, error) {
	return specv1.Canonicalize(token)
}

// Decode parses a capability token from its JSON encoding.
func Decode(data []byte) (specv1.CapabilityToken, error) {
	var token specv1.CapabilityToken
	if err := json.Unmarshal(data, &token); err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("identity: decode token: %w", err)
	}
	return token, nil
}

func newTokenID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "cap_" + tokenIDEncoding.EncodeToString(buf), nil
}

// CheckIntent reports whether token may act on intentID. A repository-level
// token (Intent == specv1.CapabilityTokenAnyIntent) may act on any intent; any
// other token only on the intent it is bound to.
func CheckIntent(token specv1.CapabilityToken, intentID string) error {
	if token.Intent == specv1.CapabilityTokenAnyIntent || token.Intent == intentID {
		return nil
	}
	return fmt.Errorf("%w: token is for %s, not %s", ErrIntentMismatch, token.Intent, intentID)
}

// CheckPrincipal reports whether token was issued to principal.
func CheckPrincipal(token specv1.CapabilityToken, principal string) error {
	if token.Principal != principal {
		return fmt.Errorf("%w: token is for %s, caller is %s", ErrPrincipalMismatch, token.Principal, principal)
	}
	return nil
}

// Bearer encodes a token for an HTTP Authorization header or a Git credential:
// the canonical JSON, base64url without padding.
func Bearer(token specv1.CapabilityToken) (string, error) {
	data, err := Encode(token)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// ParseBearer decodes a token written by Bearer. Standard and padded base64 are
// accepted as well, since credential helpers and shells are not always careful.
func ParseBearer(s string) (specv1.CapabilityToken, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if data, err := enc.DecodeString(s); err == nil {
			return Decode(data)
		}
	}
	return specv1.CapabilityToken{}, fmt.Errorf("identity: bearer token is not base64")
}

// TokenScopeAllows reports whether token's own scope permits path. It does not
// verify the token: callers that check many paths verify once with Verify and
// then use this for each path.
func TokenScopeAllows(token specv1.CapabilityToken, path string) (bool, error) {
	return scopeAllows(token.Scope, path)
}
