package v1

import "strings"

// Attestation is the signed provenance of one world: who produced it, with which model and tools. See spec/v1/attestation.md.
type Attestation struct {
	Attempt    string            `json:"attempt"`
	Agent      string            `json:"agent"`
	Model      string            `json:"model"`
	ModelVer   string            `json:"model_ver"`
	Tools      []string          `json:"tools"`
	PromptHash string            `json:"prompt_hash"`
	Seed       *int64            `json:"seed,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	RunBundle  string            `json:"run_bundle,omitempty"`
	TokensIn   int64             `json:"tokens_in"`
	TokensOut  int64             `json:"tokens_out"`
	CostMicros int64             `json:"cost_micros"`
	Signature  string            `json:"signature"`
}

// Validate reports whether the attestation is well formed; it checks shape, not signatures.
func (a Attestation) Validate() error {
	if !validContentID(a.Attempt, "att_") || !validPrincipalID(a.Agent) || strings.TrimSpace(a.Model) == "" || strings.TrimSpace(a.ModelVer) == "" || len(a.Tools) == 0 || !validHexDigest(a.PromptHash) || a.TokensIn < 0 || a.TokensOut < 0 || a.CostMicros < 0 || strings.TrimSpace(a.Signature) == "" {
		return ErrInvalidAttestation
	}
	for _, tool := range a.Tools {
		if strings.TrimSpace(tool) == "" {
			return ErrInvalidAttestation
		}
	}
	return nil
}
