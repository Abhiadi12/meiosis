package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// enforcingServer returns a test server with token enforcement on, plus the
// issuer's key pair.
func enforcingServer(t *testing.T) (*Server, crypto.KeyPair) {
	t.Helper()
	backend, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	agent, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(graph.NewStore(backend), "agent:impl-3", agent.PrivateKey)
	s.IssuerKey = issuer.PublicKey
	testBackends[s] = backend
	return s, issuer
}

// testBackends maps a test server to the storage backend it was built on.
var testBackends = map[*Server]storage.Store{}

func backendOf(s *Server) storage.Store { return testBackends[s] }

func issueToken(t *testing.T, issuer crypto.KeyPair, principal, intent string) json.RawMessage {
	t.Helper()
	token, err := identity.Issue(identity.IssueParams{
		Principal: principal,
		Intent:    intent,
		IssuedBy:  "human:lakin",
		Scope:     specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
	}, issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := identity.Encode(token)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func createIntent(t *testing.T, s *Server, token json.RawMessage) string {
	t.Helper()
	args := `{"repo":"r","title":"t","goal":"g","acceptance":[{"text":"a"}],"scope":{"allow":["src/**"],"mode":"enforce"},"capability_token":` + string(token) + `}`
	out, err := handleIntentCreate(context.Background(), s, json.RawMessage(args))
	if err != nil {
		t.Fatalf("intent_create error = %v", err)
	}
	return out.(specv1.Intent).ID
}

func checkPath(s *Server, intentID string, token json.RawMessage) error {
	args := `{"intent":"` + intentID + `","path":"src/a.go","capability_token":` + string(token) + `}`
	_, err := handleIntentCheckPath(context.Background(), s, json.RawMessage(args))
	return err
}

func TestTokenBoundToOneIntentIsRefusedOnAnother(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	intentA := createIntent(t, s, repoToken)
	intentB := createIntent(t, s, issuerTokenWithTitle(t, s, issuer))

	boundToA := issueToken(t, issuer, s.Principal, intentA)
	if err := checkPath(s, intentA, boundToA); err != nil {
		t.Fatalf("token bound to A on A: %v", err)
	}
	err := checkPath(s, intentB, boundToA)
	if err == nil || !strings.Contains(err.Error(), "different intent") {
		t.Fatalf("token bound to A on B: err = %v, want intent mismatch", err)
	}
	if err := checkPath(s, intentB, repoToken); err != nil {
		t.Fatalf("repo-level token on B: %v", err)
	}
}

// issuerTokenWithTitle creates a second, distinct intent so two intent IDs exist.
func issuerTokenWithTitle(t *testing.T, s *Server, issuer crypto.KeyPair) json.RawMessage {
	t.Helper()
	token := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	args := `{"repo":"r2","title":"other","goal":"g","acceptance":[{"text":"a"}],"scope":{"allow":["src/**"],"mode":"enforce"},"capability_token":` + string(token) + `}`
	if _, err := handleIntentCreate(context.Background(), s, json.RawMessage(args)); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestIntentBoundTokenCannotCreateIntents(t *testing.T) {
	s, issuer := enforcingServer(t)
	bound := issueToken(t, issuer, s.Principal, "int_"+strings.Repeat("d", 52))
	args := `{"repo":"r","title":"t","goal":"g","acceptance":[{"text":"a"}],"scope":{"allow":["**"],"mode":"enforce"},"capability_token":` + string(bound) + `}`
	if _, err := handleIntentCreate(context.Background(), s, json.RawMessage(args)); err == nil {
		t.Fatal("intent_create accepted a token bound to a specific intent")
	}
}

func TestTokenIssuedToAnotherPrincipalIsRefused(t *testing.T) {
	s, issuer := enforcingServer(t)
	foreign := issueToken(t, issuer, "agent:someone-else", specv1.CapabilityTokenAnyIntent)
	args := `{"repo":"r","title":"t","goal":"g","acceptance":[{"text":"a"}],"scope":{"allow":["**"],"mode":"enforce"},"capability_token":` + string(foreign) + `}`
	if _, err := handleIntentCreate(context.Background(), s, json.RawMessage(args)); err == nil {
		t.Fatal("intent_create accepted a token issued to a different principal")
	}
}

func TestEvidenceSubmitHonoursTokenIntentBinding(t *testing.T) {
	s, issuer := enforcingServer(t)
	attempt := putAttempt(t, s, "agent:other-author")
	submit := func(token json.RawMessage) error {
		args := `{"attempt":"` + attempt.ID + `","world":"0000000000000000000000000000000000000000000000000000000000000001","kind":"test-run","outcome":"pass","payload":{"ok":true},"capability_token":` + string(token) + `}`
		_, err := handleEvidenceSubmit(context.Background(), s, json.RawMessage(args))
		return err
	}
	if err := submit(issueToken(t, issuer, s.Principal, "int_"+strings.Repeat("e", 52))); err == nil {
		t.Fatal("evidence_submit accepted a token bound to a different intent than the attempt's")
	}
	if err := submit(issueToken(t, issuer, s.Principal, attempt.Intent)); err != nil {
		t.Fatalf("evidence_submit with a token bound to the attempt's intent: %v", err)
	}
}

func TestRevokedTokenIsRefusedAcrossStoreInstances(t *testing.T) {
	s, issuer := enforcingServer(t)
	s.Revocation = identity.NewStoreRevocationList(backendOf(s))
	encoded := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	id := createIntent(t, s, encoded)

	token, err := identity.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// Revoke through a separately constructed list over the same backend, as
	// the CLI does while the daemon is running.
	if err := identity.NewStoreRevocationList(backendOf(s)).Revoke(context.Background(), token.ID); err != nil {
		t.Fatal(err)
	}
	if err := checkPath(s, id, encoded); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked token: err = %v, want revoked", err)
	}
}

func mustIssue(t *testing.T, issuer crypto.KeyPair, principal, intent string, scope specv1.Scope) json.RawMessage {
	t.Helper()
	token, err := identity.Issue(identity.IssueParams{Principal: principal, Intent: intent, IssuedBy: "human:lakin", Scope: scope}, issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := identity.Encode(token)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
