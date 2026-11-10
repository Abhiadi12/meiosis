package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

type attemptEnv struct {
	store   *graph.Store
	backend storage.Store
	keys    crypto.KeyPair
}

func newAttemptEnv(t *testing.T) *attemptEnv {
	t.Helper()
	backend, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &attemptEnv{store: graph.NewStore(backend), backend: backend, keys: keys}
}

func (e *attemptEnv) intent(t *testing.T, mode specv1.ScopeMode) specv1.Intent {
	t.Helper()
	intent, err := e.store.CreateIntent(context.Background(), graph.CreateIntentParams{
		Repo: "r", Title: "t", Goal: "g",
		Acceptance: []specv1.Criterion{{Text: "ok"}},
		Scope:      specv1.Scope{Allow: []string{"src/**"}, Deny: []string{"src/secret/**"}, Mode: mode},
		CreatedBy:  "human:lakin",
	}, e.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func (e *attemptEnv) open(t *testing.T, intent specv1.Intent) specv1.Attempt {
	t.Helper()
	attempt, err := e.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{Intent: intent.ID, Author: "agent:impl"}, e.keys.PrivateKey)
	if err != nil {
		t.Fatalf("OpenAttempt() error = %v", err)
	}
	return attempt
}

func (e *attemptEnv) write(attempt specv1.Attempt, path, content string) (graph.WriteResult, error) {
	return e.store.WriteFile(context.Background(), graph.WriteParams{
		Attempt: attempt.ID, Author: "agent:impl", Path: path, Content: []byte(content),
	}, e.keys.PrivateKey)
}

func TestOpenAttemptIsSignedAndOpen(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))

	if attempt.Status != specv1.AttemptStatusOpen || attempt.World != graph.EmptyWorld() || attempt.BaseWorld != graph.EmptyWorld() {
		t.Fatalf("attempt = %+v, want open on the empty world", attempt)
	}
	ok, err := crypto.Verify(attempt, attempt.Signature, env.keys.PublicKey)
	if err != nil || !ok {
		t.Fatalf("attempt signature invalid: %v, %v", ok, err)
	}
	stored, err := env.store.GetAttempt(context.Background(), attempt.ID)
	if err != nil || stored.ID != attempt.ID {
		t.Fatalf("GetAttempt() = %+v, %v", stored, err)
	}
}

func TestOpenAttemptRequiresAnOpenIntent(t *testing.T) {
	env := newAttemptEnv(t)
	_, err := env.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{
		Intent: "int_" + strings.Repeat("z", 52), Author: "agent:impl",
	}, env.keys.PrivateKey)
	if err == nil {
		t.Fatal("OpenAttempt() on an unknown intent succeeded")
	}
}

func TestOpenAttemptRejectsUnknownBaseWorld(t *testing.T) {
	env := newAttemptEnv(t)
	intent := env.intent(t, specv1.ScopeModeEnforce)
	_, err := env.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{
		Intent: intent.ID, Author: "agent:impl", BaseWorld: specv1.MustParseWorldHash(strings.Repeat("ab", 32)),
	}, env.keys.PrivateKey)
	if !errors.Is(err, graph.ErrUnknownWorld) {
		t.Fatalf("OpenAttempt() error = %v, want ErrUnknownWorld", err)
	}
}

func TestWriteFileEnforceRejectsOutOfScopeAndStoresNothing(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))

	for path, wantReason := range map[string]string{
		"docs/readme.md":     "matches no allow rule",
		"src/secret/key.pem": `matches deny rule "src/secret/**"`,
	} {
		_, err := env.write(attempt, path, "x")
		var scopeErr *graph.ScopeError
		if !errors.Is(err, graph.ErrScopeViolation) || !errors.As(err, &scopeErr) {
			t.Fatalf("write %s: error = %v, want a ScopeError", path, err)
		}
		if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), wantReason) {
			t.Fatalf("write %s: message %q should name the path and the rule %q", path, err, wantReason)
		}
	}

	written, _, err := env.store.WorkspaceFiles(context.Background(), attempt.ID)
	if err != nil || len(written) != 0 {
		t.Fatalf("workspace = %v, %v; want empty after rejected writes", written, err)
	}
	stored, _ := env.store.GetAttempt(context.Background(), attempt.ID)
	if len(stored.ScopeViolations) != 0 {
		t.Fatalf("enforce-mode rejections must not be recorded as violations: %+v", stored.ScopeViolations)
	}
}

func TestWriteFileWarnRecordsViolationOnce(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeWarn))

	result, err := env.write(attempt, "docs/readme.md", "v1")
	if err != nil {
		t.Fatalf("warn-mode write error = %v", err)
	}
	if result.Violation == nil || result.Violation.Path != "docs/readme.md" {
		t.Fatalf("Violation = %+v, want one for docs/readme.md", result.Violation)
	}
	if _, err = env.write(attempt, "docs/readme.md", "v2"); err != nil {
		t.Fatal(err)
	}
	if _, err = env.write(attempt, "src/ok.go", "package src"); err != nil {
		t.Fatal(err)
	}

	stored, _ := env.store.GetAttempt(context.Background(), attempt.ID)
	if len(stored.ScopeViolations) != 1 {
		t.Fatalf("ScopeViolations = %+v, want exactly one (deduplicated, in-scope write adds none)", stored.ScopeViolations)
	}
	ok, err := crypto.Verify(stored, stored.Signature, env.keys.PublicKey)
	if err != nil || !ok {
		t.Fatalf("attempt must be re-signed after recording a violation: %v, %v", ok, err)
	}
}

func TestWriteFileRejectsNonAuthorAndUnsafePaths(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))

	_, err := env.store.WriteFile(context.Background(), graph.WriteParams{
		Attempt: attempt.ID, Author: "agent:intruder", Path: "src/a.go", Content: []byte("x"),
	}, env.keys.PrivateKey)
	if !errors.Is(err, graph.ErrNotAuthor) {
		t.Fatalf("non-author write error = %v, want ErrNotAuthor", err)
	}
	for _, path := range []string{"../etc/passwd", "/abs", "src/../../x", ""} {
		if _, err := env.write(attempt, path, "x"); err == nil {
			t.Fatalf("write %q succeeded, want an error", path)
		}
	}
}

func TestCommitBindsWorldHashIndependentOfWriteOrder(t *testing.T) {
	commitWith := func(order [][2]string) specv1.WorldHash {
		env := newAttemptEnv(t)
		attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
		for _, f := range order {
			if _, err := env.write(attempt, f[0], f[1]); err != nil {
				t.Fatal(err)
			}
		}
		res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return res.Attempt.World
	}
	a := commitWith([][2]string{{"src/a.go", "A"}, {"src/b.go", "B"}})
	b := commitWith([][2]string{{"src/b.go", "B"}, {"src/a.go", "A"}})
	c := commitWith([][2]string{{"src/a.go", "A"}, {"src/b.go", "different"}})
	if a != b {
		t.Fatal("identical content must hash identically regardless of write order")
	}
	if a == c || a == graph.EmptyWorld() {
		t.Fatal("different content must produce a different world hash")
	}
}

func TestCommitRecordsSignedProvenanceAndNeverStoresPrompt(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
	if _, err := env.write(attempt, "src/a.go", "package src"); err != nil {
		t.Fatal(err)
	}

	const prompt = "SECRET-PROMPT-TEXT api_key=hunter2"
	res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{
		Attempt: attempt.ID, Author: "agent:impl",
		Model: "claude-opus-5", ModelVer: "2026-01", Tools: []string{"editor"},
		Prompt: prompt, TokensIn: 10, TokensOut: 20, CostMicros: 300,
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	att := res.Attestation
	if att.Agent != "agent:impl" || att.Model != "claude-opus-5" || att.TokensOut != 20 || len(att.PromptHash) != 64 {
		t.Fatalf("attestation = %+v", att)
	}
	if ok, verr := crypto.Verify(att, att.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatalf("attestation signature invalid: %v, %v", ok, verr)
	}

	stored, err := env.store.GetAttestation(context.Background(), attempt.ID, res.Attempt.World)
	if err != nil || stored.PromptHash != att.PromptHash {
		t.Fatalf("GetAttestation() = %+v, %v", stored, err)
	}
	records, _ := env.backend.List(context.Background(), storage.KindAttestation)
	for _, data := range records {
		if strings.Contains(string(data), "hunter2") || strings.Contains(string(data), "SECRET-PROMPT") {
			t.Fatal("the prompt text was stored; only its digest may be (NFR-4.2)")
		}
	}
}

func TestCommitWithoutReportedProvenanceRecordsUnknown(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
	if _, err := env.write(attempt, "src/a.go", "x"); err != nil {
		t.Fatal(err)
	}
	res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if res.Attestation.Model != "unknown" || res.Attestation.ModelVer != "unknown" {
		t.Fatalf("unreported model should be recorded as unknown, got %+v", res.Attestation)
	}
}

func TestCommitHandlesDeletionsAndRecommit(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
	commit := func() graph.CommitResult {
		res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	_, _ = env.write(attempt, "src/a.go", "A")
	_, _ = env.write(attempt, "src/b.go", "B")
	first := commit()

	if _, err := env.store.WriteFile(context.Background(), graph.WriteParams{Attempt: attempt.ID, Author: "agent:impl", Path: "src/b.go", Delete: true}, env.keys.PrivateKey); err != nil {
		t.Fatal(err)
	}
	second := commit()
	if second.Attempt.World == first.Attempt.World {
		t.Fatal("recommit after a deletion must change the world hash")
	}
	if len(second.Files) != 1 || second.Files[0] != "src/a.go" {
		t.Fatalf("Files = %v, want only src/a.go", second.Files)
	}
}

func TestOpenAttemptFromCommittedBaseWorldStartsWithItsFiles(t *testing.T) {
	env := newAttemptEnv(t)
	intent := env.intent(t, specv1.ScopeModeEnforce)
	first := env.open(t, intent)
	_, _ = env.write(first, "src/a.go", "A")
	res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: first.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	second, err := env.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{
		Intent: intent.ID, Author: "agent:impl", BaseWorld: res.Attempt.World,
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = env.write(second, "src/b.go", "B")
	res2, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: second.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Files) != 2 {
		t.Fatalf("Files = %v, want the base file plus the new one", res2.Files)
	}
	if len(res2.Changed) != 1 || res2.Changed[0] != "src/b.go" {
		t.Fatalf("Changed = %v, want only src/b.go (diff against base)", res2.Changed)
	}
}

func TestAttemptReportShowsEvidenceFreshness(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
	_, _ = env.write(attempt, "src/a.go", "A")
	res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	submit := func(world specv1.WorldHash) {
		_, sErr := env.store.SubmitEvidence(context.Background(), graph.SubmitEvidenceParams{
			Attempt: attempt.ID, Producer: "agent:ci", World: world, Kind: specv1.EvidenceKindTestRun,
			Outcome: specv1.EvidenceOutcomePass, Payload: []byte(`{"ok":true}`),
		}, env.keys.PrivateKey)
		if sErr != nil {
			t.Fatal(sErr)
		}
	}
	submit(res.Attempt.World)
	submit(graph.EmptyWorld()) // evidence for a superseded world

	report, err := graph.BuildAttemptReport(context.Background(), env.store, res.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Committed || report.Attestation == nil || len(report.Evidence) != 2 {
		t.Fatalf("report = %+v", report)
	}
	fresh := 0
	for _, e := range report.Evidence {
		if e.Fresh {
			fresh++
		}
		if !e.Independent {
			t.Fatalf("evidence from agent:ci on agent:impl's attempt should be independent: %+v", e)
		}
	}
	if fresh != 1 {
		t.Fatalf("fresh evidence count = %d, want exactly 1 (the one bound to the current world)", fresh)
	}
}

func TestListAttemptsFiltersByIntent(t *testing.T) {
	env := newAttemptEnv(t)
	a := env.intent(t, specv1.ScopeModeEnforce)
	b, err := env.store.CreateIntent(context.Background(), graph.CreateIntentParams{
		Repo: "r", Title: "other", Goal: "g", Acceptance: []specv1.Criterion{{Text: "ok"}},
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}, CreatedBy: "human:lakin",
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	env.open(t, a)
	env.open(t, b)
	all, _ := env.store.ListAttempts(context.Background(), "")
	onlyA, _ := env.store.ListAttempts(context.Background(), a.ID)
	if len(all) != 2 || len(onlyA) != 1 || onlyA[0].Intent != a.ID {
		t.Fatalf("all = %d, onlyA = %+v", len(all), onlyA)
	}
}

// ---- append-only guarantees (spec/v1 README §3.1, SRS §4.4) -----------------

func rawAttempt(t *testing.T, env *attemptEnv, kind storage.Kind, id string) []byte {
	t.Helper()
	data, err := env.backend.Get(context.Background(), kind, id)
	if err != nil {
		t.Fatalf("Get(%s, %s) error = %v", kind, id, err)
	}
	return data
}

func TestAttemptCreationRecordNeverChanges(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeWarn))
	before := rawAttempt(t, env, storage.KindAttempt, attempt.ID)

	_, _ = env.write(attempt, "docs/outside.md", "x") // warn: records a violation
	_, _ = env.write(attempt, "src/a.go", "A")
	res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	if after := rawAttempt(t, env, storage.KindAttempt, attempt.ID); string(after) != string(before) {
		t.Fatalf("the attempt's creation record was rewritten:\nbefore %s\n after %s", before, after)
	}

	// The mutable view lives in the separate state snapshot and is signed.
	state := rawAttempt(t, env, storage.KindAttemptState, attempt.ID)
	var snapshot specv1.Attempt
	if err = json.Unmarshal(state, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.World != res.Attempt.World || len(snapshot.ScopeViolations) != 1 {
		t.Fatalf("state snapshot = %+v, want the committed world and one violation", snapshot)
	}
	if ok, verr := crypto.Verify(snapshot, snapshot.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatalf("state snapshot signature invalid: %v, %v", ok, verr)
	}
	current, err := env.store.GetAttempt(context.Background(), attempt.ID)
	if err != nil || current.World != res.Attempt.World {
		t.Fatalf("GetAttempt() = %+v, %v; want the current view", current, err)
	}
	listed, _ := env.store.ListAttempts(context.Background(), "")
	if len(listed) != 1 || listed[0].World != res.Attempt.World {
		t.Fatalf("ListAttempts() must return the current view, got %+v", listed)
	}
}

func TestAttestationsAreImmutableAndKeptPerWorld(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
	commit := func(model string) graph.CommitResult {
		res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl", Model: model, ModelVer: "1"}, env.keys.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	_, _ = env.write(attempt, "src/a.go", "A")
	first := commit("model-one")

	// Recommitting the identical world keeps the original provenance.
	again := commit("model-two")
	if again.Attempt.World != first.Attempt.World || again.Attestation.Model != "model-one" {
		t.Fatalf("recommit of the same world rewrote its attestation: %+v", again.Attestation)
	}

	// A new world gets its own attestation; the earlier one is retained.
	_, _ = env.write(attempt, "src/b.go", "B")
	second := commit("model-two")
	if second.Attempt.World == first.Attempt.World || second.Attestation.Model != "model-two" {
		t.Fatalf("second world attestation = %+v", second.Attestation)
	}
	old, err := env.store.GetAttestation(context.Background(), attempt.ID, first.Attempt.World)
	if err != nil || old.Model != "model-one" {
		t.Fatalf("attestation for the first world = %+v, %v; want it retained unchanged", old, err)
	}
}

func TestWorkingSetIsNotStoredInTheWorldsTable(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))
	_, _ = env.write(attempt, "src/a.go", "A")
	worlds, err := env.backend.List(context.Background(), storage.KindWorld)
	if err != nil || len(worlds) != 0 {
		t.Fatalf("worlds table = %d records, %v; want none before a commit (worlds are append-only)", len(worlds), err)
	}
	if _, err := env.backend.Get(context.Background(), storage.KindWorkspace, attempt.ID); err != nil {
		t.Fatalf("working set not found in the workspaces table: %v", err)
	}
}

func TestPutAttemptCannotChangeIdentityFields(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := env.open(t, env.intent(t, specv1.ScopeModeEnforce))

	tampered := attempt
	tampered.Author = "agent:someone-else"
	if err := env.store.PutAttempt(context.Background(), tampered); !errors.Is(err, graph.ErrImmutable) {
		t.Fatalf("PutAttempt() with a changed author = %v, want ErrImmutable", err)
	}
	abandoned := attempt
	abandoned.Status = specv1.AttemptStatusAbandoned
	if err := env.store.PutAttempt(context.Background(), abandoned); err != nil {
		t.Fatalf("status change via state snapshot rejected: %v", err)
	}
	if got, _ := env.store.GetAttempt(context.Background(), attempt.ID); got.Status != specv1.AttemptStatusAbandoned {
		t.Fatalf("current status = %s, want abandoned", got.Status)
	}
	if raw := rawAttempt(t, env, storage.KindAttempt, attempt.ID); !strings.Contains(string(raw), `"status":"open"`) {
		t.Fatalf("creation record must still say open: %s", raw)
	}
}

func TestEvidenceAndIntentCannotBeOverwritten(t *testing.T) {
	env := newAttemptEnv(t)
	intent := env.intent(t, specv1.ScopeModeEnforce)
	attempt := env.open(t, intent)
	ev, err := env.store.SubmitEvidence(context.Background(), graph.SubmitEvidenceParams{
		Attempt: attempt.ID, Producer: "agent:ci", World: attempt.World, Kind: specv1.EvidenceKindTestRun,
		Outcome: specv1.EvidenceOutcomePass, Payload: []byte(`{"ok":true}`),
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	forged := ev
	forged.Outcome = specv1.EvidenceOutcomeFail
	forged.Signature = "forged"
	if err := env.store.PutEvidence(context.Background(), forged); !errors.Is(err, graph.ErrImmutable) {
		t.Fatalf("overwriting stored evidence = %v, want ErrImmutable", err)
	}
	if stored, _ := env.store.GetEvidence(context.Background(), ev.ID); stored.Outcome != specv1.EvidenceOutcomePass {
		t.Fatalf("stored evidence outcome = %s, want pass", stored.Outcome)
	}
}
