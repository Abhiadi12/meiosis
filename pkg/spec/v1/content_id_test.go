package v1

import (
	"testing"
	"time"
)

func validContentIDFixtureIntent() Intent {
	return Intent{
		Repo: "github.com/example/repo", Title: "Add feature", Goal: "Implement feature",
		Acceptance: []Criterion{{Text: "tests pass"}}, Scope: Scope{Allow: []string{"pkg/**"}, Mode: ScopeModeEnforce},
		CreatedBy: "human:lakin", CreatedAt: time.Unix(1, 0), Status: IntentStatusOpen,
	}
}

func TestNewContentIDIsDeterministicAndValid(t *testing.T) {
	intent := validContentIDFixtureIntent()

	id, err := NewContentID("int_", intent)
	if err != nil {
		t.Fatalf("NewContentID() error = %v", err)
	}
	if !validContentID(id, "int_") {
		t.Fatalf("NewContentID() = %q, not a valid int_ content ID", id)
	}

	again, err := NewContentID("int_", intent)
	if err != nil {
		t.Fatalf("NewContentID() error = %v", err)
	}
	if id != again {
		t.Fatalf("NewContentID() not deterministic: %q != %q", id, again)
	}
}

func TestNewContentIDChangesWithContent(t *testing.T) {
	a := validContentIDFixtureIntent()
	b := a
	b.Title = a.Title + " (variant)"

	idA, err := NewContentID("int_", a)
	if err != nil {
		t.Fatalf("NewContentID() error = %v", err)
	}
	idB, err := NewContentID("int_", b)
	if err != nil {
		t.Fatalf("NewContentID() error = %v", err)
	}
	if idA == idB {
		t.Fatal("NewContentID() produced the same ID for different content")
	}
}
