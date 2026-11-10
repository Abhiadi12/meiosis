package identity

import "errors"

var (
	ErrInvalidParams = errors.New("identity: invalid issue parameters")
	ErrTokenAltered  = errors.New("identity: capability token signature invalid")
	ErrTokenExpired  = errors.New("identity: capability token expired")
	ErrTokenRevoked  = errors.New("identity: capability token revoked")
	ErrScopeDenied   = errors.New("identity: capability token does not permit this path")
)

// ErrIntentMismatch is returned when a token bound to one intent is presented
// for another.
var ErrIntentMismatch = errors.New("identity: capability token is bound to a different intent")

// ErrPrincipalMismatch is returned when a token issued to one principal is
// presented by another.
var ErrPrincipalMismatch = errors.New("identity: capability token was issued to a different principal")

var (
	// ErrWidening is returned when a delegated token would hold more authority
	// than the token it was delegated from (FR-1.5).
	ErrWidening = errors.New("identity: delegation would widen the parent's authority")
	// ErrNotDelegable is returned when a token cannot be delegated from.
	ErrNotDelegable = errors.New("identity: capability token cannot be delegated")
	// ErrOperationDenied is returned when a token does not permit an operation.
	ErrOperationDenied = errors.New("identity: capability token does not permit this operation")
	// ErrRootNotHuman is returned when a delegation chain does not start at a human.
	ErrRootNotHuman = errors.New("identity: delegation chain does not start at a human principal")
	// ErrSpendCeiling is returned when reported cost would exceed a token's ceiling.
	ErrSpendCeiling = errors.New("identity: spend ceiling exceeded")
)
