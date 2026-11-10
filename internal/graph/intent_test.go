package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

func newTestStore(t *testing.T) *graph.Store {
	t.Helper()
	backend, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return graph.NewStore(backend)
}

func TestCreateIntentThenGetIntentRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	params := graph.CreateIntentParams{
		Repo:       "github.com/example/repo",
		Title:      "Add feature",
		Goal:       "Implement the feature",
		Acceptance: []specv1.Criterion{{Text: "tests pass"}},
		Scope:      specv1.Scope{Allow: []string{"pkg/**"}, Mode: specv1.ScopeModeEnforce},
		CreatedBy:  "agent:impl-3",
	}

	created, err := store.CreateIntent(ctx, params, keys.PrivateKey)
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}
	if validateErr := created.Validate(); validateErr != nil {
		t.Fatalf("created Intent.Validate() error = %v", validateErr)
	}
	ok, err := crypto.Verify(created, created.Signature, keys.PublicKey)
	if err != nil || !ok {
		t.Fatalf("crypto.Verify() = %v, %v, want true, nil", ok, err)
	}

	fetched, err := store.GetIntent(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetIntent() error = %v", err)
	}
	if fetched.ID != created.ID || fetched.Title != created.Title {
		t.Fatalf("GetIntent() = %+v, want %+v", fetched, created)
	}

	all, err := store.ListIntents(ctx)
	if err != nil {
		t.Fatalf("ListIntents() error = %v", err)
	}
	if len(all) != 1 || all[0].ID != created.ID {
		t.Fatalf("ListIntents() = %+v, want exactly the created intent", all)
	}
}

func TestCreateIntentIDIsContentDerived(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	params := graph.CreateIntentParams{
		Repo: "github.com/example/repo", Title: "Add feature", Goal: "Implement the feature",
		Acceptance: []specv1.Criterion{{Text: "tests pass"}},
		Scope:      specv1.Scope{Allow: []string{"pkg/**"}, Mode: specv1.ScopeModeEnforce},
		CreatedBy:  "agent:impl-3",
	}

	first, err := store.CreateIntent(ctx, params, keys.PrivateKey)
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	params.Title = "A different feature"
	second, err := store.CreateIntent(ctx, params, keys.PrivateKey)
	if err != nil {
		t.Fatalf("CreateIntent() error = %v", err)
	}

	if first.ID == second.ID {
		t.Fatal("CreateIntent() produced the same ID for different content")
	}
}

const (
	testAttemptID = "att_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testWorld     = "0000000000000000000000000000000000000000000000000000000000000001"
)

// putTestAttempt persists an open attempt by author and returns it.
func putTestAttempt(t *testing.T, store *graph.Store, author string) specv1.Attempt {
	t.Helper()
	world := specv1.MustParseWorldHash(testWorld)
	attempt := specv1.Attempt{
		ID:        testAttemptID,
		Intent:    "int_" + "cccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Author:    author,
		World:     world,
		BaseWorld: world,
		Status:    specv1.AttemptStatusOpen,
		CreatedAt: time.Unix(1, 0).UTC(),
		Signature: "sig",
	}
	if err := store.PutAttempt(context.Background(), attempt); err != nil {
		t.Fatalf("PutAttempt() error = %v", err)
	}
	return attempt
}

func evidenceParams(producer string) graph.SubmitEvidenceParams {
	return graph.SubmitEvidenceParams{
		Attempt:  testAttemptID,
		Producer: producer,
		World:    specv1.MustParseWorldHash(testWorld),
		Kind:     specv1.EvidenceKindTestRun,
		Outcome:  specv1.EvidenceOutcomePass,
		Payload:  json.RawMessage(`{"passed":42,"failed":0}`),
	}
}

func TestSubmitEvidenceRejectsUnknownAttempt(t *testing.T) {
	store := newTestStore(t)
	keys, _ := crypto.GenerateKeyPair()
	if _, err := store.SubmitEvidence(context.Background(), evidenceParams("agent:ci-runner"), keys.PrivateKey); err == nil {
		t.Fatal("SubmitEvidence() accepted evidence for an attempt that does not exist")
	}
}

func TestSubmitEvidenceRejectsInactiveAttempt(t *testing.T) {
	store := newTestStore(t)
	keys, _ := crypto.GenerateKeyPair()
	attempt := putTestAttempt(t, store, "agent:author")
	attempt.Status = specv1.AttemptStatusAbandoned
	if err := store.PutAttempt(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SubmitEvidence(context.Background(), evidenceParams("agent:ci-runner"), keys.PrivateKey); !errors.Is(err, graph.ErrInactiveAttempt) {
		t.Fatalf("SubmitEvidence() error = %v, want ErrInactiveAttempt", err)
	}
}

func TestSubmitEvidenceComputesIndependence(t *testing.T) {
	store := newTestStore(t)
	keys, _ := crypto.GenerateKeyPair()
	putTestAttempt(t, store, "agent:author")

	self, err := store.SubmitEvidence(context.Background(), evidenceParams("agent:author"), keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if self.Independent {
		t.Fatal("evidence produced by the attempt's author must not be independent")
	}
	other, err := store.SubmitEvidence(context.Background(), evidenceParams("agent:ci-runner"), keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !other.Independent {
		t.Fatal("evidence produced by someone other than the author must be independent")
	}
	stored, err := store.GetEvidence(context.Background(), other.ID)
	if err != nil || !stored.Independent {
		t.Fatalf("stored evidence Independent = %v, err = %v; want true", stored.Independent, err)
	}
}

func TestPutEvidenceRejectsForgedIndependence(t *testing.T) {
	store := newTestStore(t)
	keys, _ := crypto.GenerateKeyPair()
	putTestAttempt(t, store, "agent:author")

	evidence, err := store.SubmitEvidence(context.Background(), evidenceParams("agent:author"), keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Independent = true
	if err := store.PutEvidence(context.Background(), evidence); !errors.Is(err, graph.ErrInvalidParams) {
		t.Fatalf("PutEvidence() error = %v, want ErrInvalidParams for a forged independence flag", err)
	}
}

func TestPutAttemptStoresCanonicalJSON(t *testing.T) {
	backend, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	store := graph.NewStore(backend)
	attempt := putTestAttempt(t, store, "agent:author")

	raw, err := backend.Get(context.Background(), storage.KindAttempt, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := specv1.Canonicalize(attempt)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(canonical) {
		t.Fatalf("stored attempt is not canonical:\n got %s\nwant %s", raw, canonical)
	}
}

func TestSubmitEvidenceThenGetEvidenceRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	putTestAttempt(t, store, "agent:author")
	params := evidenceParams("agent:ci-runner")

	created, err := store.SubmitEvidence(ctx, params, keys.PrivateKey)
	if err != nil {
		t.Fatalf("SubmitEvidence() error = %v", err)
	}
	if validateErr := created.Validate(); validateErr != nil {
		t.Fatalf("created Evidence.Validate() error = %v", validateErr)
	}
	ok, err := crypto.Verify(created, created.Signature, keys.PublicKey)
	if err != nil || !ok {
		t.Fatalf("crypto.Verify() = %v, %v, want true, nil", ok, err)
	}

	fetched, err := store.GetEvidence(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetEvidence() error = %v", err)
	}
	if fetched.ID != created.ID || fetched.Attempt != created.Attempt {
		t.Fatalf("GetEvidence() = %+v, want %+v", fetched, created)
	}
}

func TestSubmitEvidenceRejectsMalformedAttempt(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	params := graph.SubmitEvidenceParams{
		Attempt:  "not-an-attempt-id",
		Producer: "agent:ci-runner",
		World:    specv1.MustParseWorldHash("0000000000000000000000000000000000000000000000000000000000000001"),
		Kind:     specv1.EvidenceKindTestRun,
		Outcome:  specv1.EvidenceOutcomePass,
		Payload:  json.RawMessage(`{"passed":42,"failed":0}`),
	}

	if _, err := store.SubmitEvidence(ctx, params, keys.PrivateKey); err == nil {
		t.Fatal("SubmitEvidence() expected error for malformed attempt ID")
	}
}
