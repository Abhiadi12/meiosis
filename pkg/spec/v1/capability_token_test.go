package v1

import (
	"testing"
	"time"
)

func validCapabilityTokenID() string {
	return "cap_" + "cccccccccccccccccccccccccccccccccccccccccccccccccccc"
}

func validCapabilityToken() CapabilityToken {
	return CapabilityToken{
		ID:        validCapabilityTokenID(),
		Principal: "agent:impl-3",
		IssuedBy:  "human:lakin",
		Intent:    validIntentID(),
		Scope:     Scope{Allow: []string{"internal/auth/**"}, Mode: ScopeModeEnforce},
		IssuedAt:  time.Unix(1, 0),
		ExpiresAt: time.Unix(1, 0).Add(time.Hour),
		Signature: "sig",
	}
}

func TestCapabilityTokenValidate(t *testing.T) {
	if err := validCapabilityToken().Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestCapabilityTokenValidateRejectsMissingFields(t *testing.T) {
	base := validCapabilityToken()
	cases := map[string]CapabilityToken{
		"bad id":        setToken(base, func(c *CapabilityToken) { c.ID = "not-an-id" }),
		"bad principal": setToken(base, func(c *CapabilityToken) { c.Principal = "not-a-principal" }),
		"bad issuer":    setToken(base, func(c *CapabilityToken) { c.IssuedBy = "not-a-principal" }),
		"bad intent":    setToken(base, func(c *CapabilityToken) { c.Intent = "not-an-intent" }),
		"zero issued":   setToken(base, func(c *CapabilityToken) { c.IssuedAt = time.Time{} }),
		"zero expiry":   setToken(base, func(c *CapabilityToken) { c.ExpiresAt = time.Time{} }),
		"no signature":  setToken(base, func(c *CapabilityToken) { c.Signature = "" }),
		"bad scope":     setToken(base, func(c *CapabilityToken) { c.Scope = Scope{} }),
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			if err := tt.Validate(); err == nil {
				t.Fatal("Validate() expected error")
			}
		})
	}
}

func TestCapabilityTokenValidateRejectsExpiryNotAfterIssuedAt(t *testing.T) {
	tt := validCapabilityToken()
	tt.ExpiresAt = tt.IssuedAt
	if err := tt.Validate(); err == nil {
		t.Fatal("Validate() expected error for expiry not after issued_at")
	}
	tt.ExpiresAt = tt.IssuedAt.Add(-time.Second)
	if err := tt.Validate(); err == nil {
		t.Fatal("Validate() expected error for expiry before issued_at")
	}
}

func TestCapabilityTokenExpired(t *testing.T) {
	tt := validCapabilityToken()
	if tt.Expired(tt.IssuedAt) {
		t.Fatal("Expired() true before expiry")
	}
	if !tt.Expired(tt.ExpiresAt) {
		t.Fatal("Expired() false exactly at expiry")
	}
	if !tt.Expired(tt.ExpiresAt.Add(time.Second)) {
		t.Fatal("Expired() false after expiry")
	}
}

func setToken(base CapabilityToken, mutate func(*CapabilityToken)) CapabilityToken {
	mutate(&base)
	return base
}
