package v1

import "strings"

// PrincipalKind distinguishes humans, agents and services.
type PrincipalKind string

// The kinds of principal.
const (
	PrincipalKindHuman PrincipalKind = "human"
	PrincipalKindAgent PrincipalKind = "agent"
)

// Principal is an identity with a public key. See spec/v1/principal.md.
type Principal struct {
	ID            string        `json:"id"`
	Kind          PrincipalKind `json:"kind"`
	DisplayName   string        `json:"display_name,omitempty"`
	PublicKey     string        `json:"public_key,omitempty"`
	DelegatedFrom string        `json:"delegated_from,omitempty"`
}

// Validate reports whether the principal is well formed.
func (p Principal) Validate() error {
	if !validPrincipalID(p.ID) || (p.Kind != PrincipalKindHuman && p.Kind != PrincipalKindAgent) {
		return ErrInvalidPrincipal
	}
	if p.DelegatedFrom != "" && !validPrincipalID(p.DelegatedFrom) {
		return ErrInvalidPrincipal
	}
	return nil
}

func validPrincipalID(value string) bool {
	parts := strings.SplitN(value, ":", 2)
	return len(parts) == 2 && (parts[0] == "human" || parts[0] == "agent") && strings.TrimSpace(parts[1]) != ""
}
