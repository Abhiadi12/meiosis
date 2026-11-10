package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestWorldHashJSON(t *testing.T) {
	h, err := ParseWorldHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("ParseWorldHash() error = %v", err)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got, want := string(b), `"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`; got != want {
		t.Fatalf("Marshal() = %s, want %s", got, want)
	}
}

func TestVerdictValidate(t *testing.T) {
	for _, decision := range []VerdictDecision{VerdictDecisionMerge, VerdictDecisionReject, VerdictDecisionEscalate} {
		tt := Verdict{Attempt: validAttemptID(), Decision: decision, DecidedBy: "human:lakin", PolicyRef: "policy @ hash", PolicyIn: json.RawMessage(`{"allow":true}`), Rationale: "reviewed", DecidedAt: time.Unix(1, 0), Signature: "sig"}
		if err := tt.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
	}
	if err := (Verdict{Attempt: validAttemptID(), Decision: "bad", DecidedBy: "human:lakin", PolicyRef: "p", PolicyIn: json.RawMessage(`{}`), Rationale: "r", DecidedAt: time.Unix(1, 0), Signature: "s"}).Validate(); err == nil {
		t.Fatal("Validate() expected error")
	}
}

func TestPrincipalValidate(t *testing.T) {
	if err := (Principal{ID: "agent:planner-7", Kind: PrincipalKindAgent}).Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if err := (Principal{Kind: PrincipalKindAgent}).Validate(); err == nil {
		t.Fatal("Validate() expected error")
	}
}

func TestAttemptValidateAndJSON(t *testing.T) {
	h := MustParseWorldHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	a := Attempt{ID: validAttemptID(), Intent: validIntentID(), Author: "human:lakin", World: h, BaseWorld: h, Status: AttemptStatusOpen, CreatedAt: time.Unix(1, 0), Signature: "sig"}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if len(b) == 0 {
		t.Fatal("Marshal() produced empty output")
	}
}

func TestEvidenceValidate(t *testing.T) {
	h := MustParseWorldHash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	e := Evidence{ID: "e1", Attempt: validAttemptID(), Kind: EvidenceKindTestRun, Producer: "human:lakin", World: h, Outcome: EvidenceOutcomePass, Payload: json.RawMessage(`{}`), CreatedAt: time.Unix(2, 0), Signature: "sig"}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestWorldHashRejectsInvalidJSON(t *testing.T) {
	var h WorldHash
	if err := json.Unmarshal([]byte(`"not-a-hash"`), &h); err == nil {
		t.Fatal("Unmarshal() expected error")
	}
}

func TestIntentValidate(t *testing.T) {
	i := Intent{
		ID: validIntentID(), Repo: "github.com/example/repo", Title: "Add feature", Goal: "Implement feature",
		Acceptance: []Criterion{{Text: "tests pass"}}, Scope: Scope{Allow: []string{"pkg/**"}, Mode: ScopeModeEnforce},
		CreatedBy: "human:lakin", CreatedAt: time.Unix(1, 0), Status: IntentStatusOpen, Signature: "sig",
	}
	if err := i.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	i.Scope.Allow = []string{"["}
	if err := i.Validate(); err == nil {
		t.Fatal("Validate() expected invalid glob error")
	}
}

func TestCanonicalizeSortsObjectKeys(t *testing.T) {
	first, err := CanonicalizeJSON([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("CanonicalizeJSON() error = %v", err)
	}
	second, err := CanonicalizeJSON([]byte(`{ "a": 1, "b": 2 }`))
	if err != nil {
		t.Fatalf("CanonicalizeJSON() error = %v", err)
	}
	if string(first) != `{"a":1,"b":2}` || string(first) != string(second) {
		t.Fatalf("canonical output mismatch: %q and %q", first, second)
	}
}

func TestCanonicalizeUsesJCSNumberRules(t *testing.T) {
	got, err := CanonicalizeJSON([]byte(`{"small":1.0,"zero":-0,"large":1e+21}`))
	if err != nil {
		t.Fatalf("CanonicalizeJSON() error = %v", err)
	}
	if want := `{"large":1e+21,"small":1,"zero":0}`; string(got) != want {
		t.Fatalf("canonical output = %q, want %q", got, want)
	}
}

func TestCanonicalizeRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{`{"a":1} {"b":2}`, `{"a":NaN}`, `{"a":1e999}`, `{"a":1,"a":2}`} {
		if _, err := CanonicalizeJSON([]byte(input)); err == nil {
			t.Fatalf("CanonicalizeJSON(%q) expected error", input)
		}
	}
}

func TestCanonicalizeMeiosisObject(t *testing.T) {
	got, err := Canonicalize(Principal{ID: "agent:planner-7", Kind: PrincipalKindAgent})
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	if want := `{"id":"agent:planner-7","kind":"agent"}`; string(got) != want {
		t.Fatalf("canonical output = %q, want %q", got, want)
	}
}

func TestCanonicalizeRejectsUnsupportedValue(t *testing.T) {
	if _, err := Canonicalize(make(chan int)); err == nil {
		t.Fatal("Canonicalize() expected unsupported value error")
	}
}

func TestCanonicalizeRepresentativeMeiosisObjects(t *testing.T) {
	hash := MustParseWorldHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	objects := []any{
		Principal{ID: "agent:planner-7", Kind: PrincipalKindAgent},
		Intent{ID: validIntentID(), Repo: "example/repo", Title: "Title", Goal: "Goal", Acceptance: []Criterion{{Text: "criterion"}}, Scope: Scope{Allow: []string{"pkg/**"}, Mode: ScopeModeEnforce}, CreatedBy: "human:lakin", CreatedAt: time.Unix(1, 0), Status: IntentStatusOpen, Signature: "sig"},
		Attempt{ID: validAttemptID(), Intent: validIntentID(), Author: "agent:planner-7", World: hash, BaseWorld: hash, Status: AttemptStatusOpen, CreatedAt: time.Unix(1, 0), Signature: "sig"},
		hash,
		Evidence{ID: "evidence-1", Attempt: validAttemptID(), World: hash, Kind: EvidenceKindTestRun, Producer: "agent:ci", Outcome: EvidenceOutcomePass, Payload: json.RawMessage(`{"passed":true}`), CreatedAt: time.Unix(1, 0), Signature: "sig"},
		Attestation{Attempt: validAttemptID(), Agent: "agent:planner-7", Model: "model", ModelVer: "v1", Tools: []string{"go test"}, PromptHash: hash.String(), TokensIn: 1, TokensOut: 1, CostMicros: 1, Signature: "sig"},
		Verdict{Attempt: validAttemptID(), Decision: VerdictDecisionMerge, DecidedBy: "human:lakin", PolicyRef: "policy", PolicyIn: json.RawMessage(`{}`), Rationale: "approved", DecidedAt: time.Unix(1, 0), Signature: "sig"},
	}
	for index, object := range objects {
		first, err := Canonicalize(object)
		if err != nil {
			t.Fatalf("object %d: first canonicalization: %v", index, err)
		}
		second, err := Canonicalize(object)
		if err != nil {
			t.Fatalf("object %d: second canonicalization: %v", index, err)
		}
		if string(first) != string(second) {
			t.Fatalf("object %d: canonical output changed: %q != %q", index, first, second)
		}
	}
}

func TestCanonicalizeDifferentObjectsDiffer(t *testing.T) {
	first, err := Canonicalize(Principal{ID: "agent:planner-7", Kind: PrincipalKindAgent})
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	second, err := Canonicalize(Principal{ID: "human:lakin", Kind: PrincipalKindHuman})
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("different objects produced identical canonical bytes")
	}
}

func TestCanonicalizeProducesStableHashInput(t *testing.T) {
	canonical, err := CanonicalizeJSON([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("CanonicalizeJSON() error = %v", err)
	}
	hash := sha256.Sum256(canonical)
	if got, want := hex.EncodeToString(hash[:]), "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"; got != want {
		t.Fatalf("canonical hash = %s, want %s", got, want)
	}
}

func TestHashCanonicalIsDeterministicAndOrderIndependent(t *testing.T) {
	first, err := HashCanonicalJSON([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("HashCanonicalJSON() error = %v", err)
	}
	second, err := HashCanonicalJSON([]byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatalf("HashCanonicalJSON() error = %v", err)
	}
	if first != second {
		t.Fatalf("hash changed with field order: %s != %s", DigestHex(first), DigestHex(second))
	}
	zero, err := HashCanonical(Principal{ID: "agent:planner-7", Kind: PrincipalKindAgent})
	if err != nil {
		t.Fatalf("HashCanonical() error = %v", err)
	}
	if zero == ([BLAKE3DigestSize]byte{}) {
		t.Fatal("HashCanonical() returned a zero digest")
	}
}

func TestHashCanonicalRejectsInvalidJSON(t *testing.T) {
	if _, err := HashCanonicalJSON([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("HashCanonicalJSON() accepted invalid JSON")
	}
}

func validIntentID() string { return "int_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }

func validAttemptID() string { return "att_" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
