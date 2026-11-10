package crypto

import "errors"

// Errors returned by this package; test with errors.Is.
var (
	ErrInvalidKey       = errors.New("invalid Ed25519 key")
	ErrKeyMismatch      = errors.New("Ed25519 public and private keys do not match")
	ErrInvalidSignature = errors.New("invalid Ed25519 signature")
)
