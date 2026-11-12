package v1

import "errors"

// Validation errors returned by the objects in this package; test with errors.Is.
var (
	ErrInvalidWorldHash       = errors.New("invalid world hash")
	ErrInvalidIdentifier      = errors.New("invalid identifier")
	ErrInvalidIntent          = errors.New("invalid intent")
	ErrInvalidPrincipal       = errors.New("invalid principal")
	ErrInvalidAttempt         = errors.New("invalid attempt")
	ErrInvalidEvidence        = errors.New("invalid evidence")
	ErrInvalidFootprint       = errors.New("invalid footprint")
	ErrInvalidAttestation     = errors.New("invalid attestation")
	ErrInvalidVerdict         = errors.New("invalid verdict")
	ErrInvalidCapabilityToken = errors.New("invalid capability token")
	ErrInvalidRefUpdate       = errors.New("invalid ref update")
	ErrInvalidOperation       = errors.New("invalid operation")
)
