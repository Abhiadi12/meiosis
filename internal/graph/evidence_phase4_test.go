package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func submit(env *attemptEnv, attempt specv1.Attempt, producer string, kind specv1.EvidenceKind, outcome specv1.EvidenceOutcome, payload string, supersedes string) (specv1.Evidence, error) {
	return env.store.SubmitEvidence(context.Background(), graph.SubmitEvidenceParams{
		Attempt: attempt.ID, Producer: producer, World: attempt.World, Kind: kind, Outcome: outcome,
		Payload: json.RawMessage(payload), Supersedes: supersedes,
	}, env.keys.PrivateKey)
}

func openedAttempt(t *testing.T, env *attemptEnv) specv1.Attempt {
	t.Helper()
	return env.open(t, env.intent(t, specv1.ScopeModeEnforce))
}

func TestBuiltinKindPayloadsAreValidatedAgainstTheirSchema(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)

	if _, err := submit(env, attempt, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{"tests": 3, "failures": 0}`, ""); err != nil {
		t.Fatalf("valid test-run payload rejected: %v", err)
	}
	for name, c := range map[string]struct {
		kind    specv1.EvidenceKind
		payload string
	}{
		"wrong type":         {specv1.EvidenceKindTestRun, `{"tests": "three"}`},
		"negative count":     {specv1.EvidenceKindTestRun, `{"failures": -1}`},
		"rate out of range":  {specv1.EvidenceKindCoverage, `{"line_rate": 1.5}`},
		"not an object":      {specv1.EvidenceKindStaticAnalysis, `[1,2]`},
		"bad nested counts":  {specv1.EvidenceKindSecurityScan, `{"vulnerabilities": {"high": "many"}}`},
		"matched not a bool": {specv1.EvidenceKindReplayMatch, `{"matched": "yes"}`},
	} {
		_, err := submit(env, attempt, "agent:ci", c.kind, specv1.EvidenceOutcomePass, c.payload, "")
		if !errors.Is(err, graph.ErrPayloadInvalid) {
			t.Errorf("%s: error = %v, want ErrPayloadInvalid", name, err)
		}
	}
}

func TestCustomKindsMustBeRegisteredAndTheirSchemaIsEnforced(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	ctx := context.Background()

	if _, err := submit(env, attempt, "agent:ci", "x-license-check", specv1.EvidenceOutcomePass, `{"approved": true}`, ""); !errors.Is(err, graph.ErrUnknownKind) {
		t.Fatalf("unregistered custom kind error = %v, want ErrUnknownKind", err)
	}

	schema := []byte(`{"type":"object","required":["approved"],"properties":{"approved":{"type":"boolean"}}}`)
	def, err := env.store.RegisterEvidenceKind(ctx, "x-license-check", schema, "human:lakin", env.keys.PrivateKey)
	if err != nil {
		t.Fatalf("RegisterEvidenceKind() error = %v", err)
	}
	if def.Signature == "" || def.RegisteredBy != "human:lakin" {
		t.Fatalf("def = %+v", def)
	}

	if _, err = submit(env, attempt, "agent:ci", "x-license-check", specv1.EvidenceOutcomePass, `{"approved": true}`, ""); err != nil {
		t.Fatalf("valid custom-kind evidence rejected: %v", err)
	}
	if _, err = submit(env, attempt, "agent:ci", "x-license-check", specv1.EvidenceOutcomePass, `{}`, ""); !errors.Is(err, graph.ErrPayloadInvalid) {
		t.Fatalf("custom payload missing a required field: error = %v, want ErrPayloadInvalid", err)
	}
	if _, err = submit(env, attempt, "agent:ci", "x-license-check", specv1.EvidenceOutcomePass, `{"approved": "yes"}`, ""); !errors.Is(err, graph.ErrPayloadInvalid) {
		t.Fatalf("custom payload with a wrong type: error = %v", err)
	}
}

func TestRegisterEvidenceKindRules(t *testing.T) {
	env := newAttemptEnv(t)
	ctx := context.Background()
	schema := []byte(`{"type":"object"}`)

	for _, bad := range []specv1.EvidenceKind{"test-run", "license-check", "x-", "x-Bad"} {
		if _, err := env.store.RegisterEvidenceKind(ctx, bad, schema, "human:lakin", env.keys.PrivateKey); !errors.Is(err, graph.ErrInvalidParams) {
			t.Errorf("RegisterEvidenceKind(%q) error = %v, want ErrInvalidParams", bad, err)
		}
	}
	if _, err := env.store.RegisterEvidenceKind(ctx, "x-ok", []byte(`{"type":"nope"}`), "human:lakin", env.keys.PrivateKey); !errors.Is(err, graph.ErrInvalidParams) {
		t.Errorf("unusable schema accepted: %v", err)
	}

	first, err := env.store.RegisterEvidenceKind(ctx, "x-ok", schema, "human:lakin", env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	again, err := env.store.RegisterEvidenceKind(ctx, "x-ok", []byte(`{ "type" : "object" }`), "human:other", env.keys.PrivateKey)
	if err != nil || again.RegisteredAt != first.RegisteredAt {
		t.Fatalf("re-registering an equivalent schema = %v %+v, want the original registration back", err, again)
	}
	_, err = env.store.RegisterEvidenceKind(ctx, "x-ok", []byte(`{"type":"array"}`), "human:lakin", env.keys.PrivateKey)
	if !errors.Is(err, graph.ErrImmutable) || !strings.Contains(err.Error(), "x-ok-v2") {
		t.Fatalf("changing a registered schema = %v, want ErrImmutable suggesting a new name", err)
	}
	if kinds, _ := env.store.ListEvidenceKinds(ctx); len(kinds) != 1 || kinds[0].Kind != "x-ok" {
		t.Fatalf("ListEvidenceKinds() = %+v", kinds)
	}
}

func TestEvidenceSupersedeCorrectsWithoutAlteringTheOriginal(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	ctx := context.Background()

	failed, err := submit(env, attempt, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomeFail, `{"tests": 3, "failures": 1}`, "")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := env.store.GetEvidence(ctx, failed.ID)

	fixed, err := submit(env, attempt, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{"tests": 3, "failures": 0}`, failed.ID)
	if err != nil {
		t.Fatalf("superseding evidence rejected: %v", err)
	}
	if fixed.Supersedes != failed.ID {
		t.Fatalf("Supersedes = %q", fixed.Supersedes)
	}
	after, _ := env.store.GetEvidence(ctx, failed.ID)
	if after.Outcome != before.Outcome || after.Signature != before.Signature {
		t.Fatal("the superseded record was altered")
	}

	report, err := graph.BuildAttemptReport(ctx, env.store, attempt)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]graph.EvidenceSummary{}
	for _, e := range report.Evidence {
		byID[e.ID] = e
	}
	if byID[failed.ID].Counted || byID[failed.ID].SupersededBy != fixed.ID {
		t.Fatalf("the superseded record must not count and must name its successor: %+v", byID[failed.ID])
	}
	if !byID[fixed.ID].Counted {
		t.Fatalf("the correcting record should count: %+v", byID[fixed.ID])
	}

	if _, err = submit(env, attempt, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{"tests": 4}`, failed.ID); !errors.Is(err, graph.ErrEvidenceSuperseded) {
		t.Fatalf("second supersede of the same record = %v, want ErrEvidenceSuperseded", err)
	}
}

// An agent must not be able to make an independent failure stop counting by
// "correcting" it with its own passing record.
func TestOnlyTheProducerMaySupersedeItsEvidence(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)

	ciFailure, err := submit(env, attempt, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomeFail, `{"failures": 2}`, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = submit(env, attempt, "agent:impl", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{"failures": 0}`, ciFailure.ID)
	if !errors.Is(err, graph.ErrSupersedeNotProducer) {
		t.Fatalf("author superseding CI evidence = %v, want ErrSupersedeNotProducer", err)
	}
}

func TestSupersedeRequiresAnExistingRecordOnTheSameAttempt(t *testing.T) {
	env := newAttemptEnv(t)
	intent := env.intent(t, specv1.ScopeModeEnforce)
	a1 := env.open(t, intent)
	a2 := env.open(t, intent)

	if _, err := submit(env, a1, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{}`, "evd_nonexistent"); !errors.Is(err, graph.ErrUnknownEvidence) {
		t.Fatalf("supersede of a missing record = %v, want ErrUnknownEvidence", err)
	}
	onA1, err := submit(env, a1, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{}`, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = submit(env, a2, "agent:ci", specv1.EvidenceKindTestRun, specv1.EvidenceOutcomePass, `{}`, onA1.ID); !errors.Is(err, graph.ErrInvalidParams) {
		t.Fatalf("supersede across attempts = %v, want ErrInvalidParams", err)
	}
}

// SRS §11.3: evidence submitted for a superseded world hash is accepted but
// marked stale, never counted.
func TestEvidenceForASupersededWorldIsAcceptedButNeverCounted(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	ctx := context.Background()
	_, _ = env.write(attempt, "src/a.go", "A")
	first, err := env.store.CommitAttempt(ctx, graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	oldWorld := first.Attempt.World
	_, _ = env.write(attempt, "src/b.go", "B")
	second, err := env.store.CommitAttempt(ctx, graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	stale, err := env.store.SubmitEvidence(ctx, graph.SubmitEvidenceParams{
		Attempt: attempt.ID, Producer: "agent:ci", World: oldWorld, Kind: specv1.EvidenceKindTestRun,
		Outcome: specv1.EvidenceOutcomePass, Payload: json.RawMessage(`{}`),
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatalf("evidence for a superseded world must be accepted: %v", err)
	}
	report, err := graph.BuildAttemptReport(ctx, env.store, second.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range report.Evidence {
		if e.ID == stale.ID && (e.Fresh || e.Counted) {
			t.Fatalf("evidence bound to the old world = %+v, want stale and not counted", e)
		}
	}
}
