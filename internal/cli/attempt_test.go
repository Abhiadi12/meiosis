package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// seededRepo initialises a repo and populates its store with one intent, one
// committed attempt (with a scope violation, since the intent is in warn mode)
// and two evidence records: one fresh and independent, one stale.
func seededRepo(t *testing.T) (root string, attempt specv1.Attempt) {
	t.Helper()
	root = initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")

	backend, err := sqlite.Open(filepath.Join(root, ".meiosis", "meiosisd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	store := graph.NewStore(backend)
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	intent, err := store.CreateIntent(ctx, graph.CreateIntentParams{
		Repo: root, Title: "Fix auth", Goal: "g", Acceptance: []specv1.Criterion{{Text: "ok"}},
		Scope: specv1.Scope{Allow: []string{"src/**"}, Mode: specv1.ScopeModeWarn}, CreatedBy: "human:lakin",
	}, keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err = store.OpenAttempt(ctx, graph.OpenAttemptParams{Intent: intent.ID, Author: "agent:impl"}, keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{"src/a.go": "A", "docs/x.md": "X"} {
		if _, err = store.WriteFile(ctx, graph.WriteParams{Attempt: attempt.ID, Author: "agent:impl", Path: path, Content: []byte(content)}, keys.PrivateKey); err != nil {
			t.Fatal(err)
		}
	}
	res, err := store.CommitAttempt(ctx, graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl", Model: "claude-opus-5", ModelVer: "1"}, keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	attempt = res.Attempt
	for _, world := range []specv1.WorldHash{attempt.World, graph.EmptyWorld()} {
		if _, err = store.SubmitEvidence(ctx, graph.SubmitEvidenceParams{
			Attempt: attempt.ID, Producer: "agent:ci", World: world, Kind: specv1.EvidenceKindTestRun,
			Outcome: specv1.EvidenceOutcomePass, Payload: []byte(`{"tests":1}`),
		}, keys.PrivateKey); err != nil {
			t.Fatal(err)
		}
	}
	return root, attempt
}

func TestAttemptListAndShow(t *testing.T) {
	root, attempt := seededRepo(t)

	list := execute(t, "attempt", "list", "--repo", root)
	if !strings.Contains(list, "agent:impl") || !strings.Contains(list, attempt.ID[:16]) {
		t.Fatalf("attempt list = %q", list)
	}

	show := execute(t, "attempt", "show", attempt.ID[:12], "--repo", root)
	for _, want := range []string{
		"agent:impl", "1 violation(s)", "docs/x.md", "claude-opus-5", "src/a.go",
		"independent, fresh", "STALE",
	} {
		if !strings.Contains(show, want) {
			t.Errorf("attempt show output missing %q:\n%s", want, show)
		}
	}

	asJSON := execute(t, "attempt", "show", attempt.ID, "--repo", root, "--format", "json")
	if !strings.Contains(asJSON, `"workspace_files"`) || !strings.Contains(asJSON, `"fresh": false`) {
		t.Fatalf("json output = %s", asJSON)
	}
}

func TestAttemptShowRejectsUnknownAndAmbiguousRefs(t *testing.T) {
	root, _ := seededRepo(t)
	for _, ref := range []string{"att_zzzz", "att_"} {
		command := New(nil)
		command.SetOut(&strings.Builder{})
		command.SetErr(&strings.Builder{})
		command.SetArgs([]string{"attempt", "show", ref, "--repo", root})
		if ref == "att_" {
			// Only one attempt exists, so the bare prefix is unique and valid.
			if err := command.Execute(); err != nil {
				t.Fatalf("unique prefix %q rejected: %v", ref, err)
			}
			continue
		}
		if err := command.Execute(); err == nil {
			t.Fatalf("unknown ref %q accepted", ref)
		}
	}
}

func TestEvidenceListShowsFreshnessAndIndependence(t *testing.T) {
	root, attempt := seededRepo(t)
	out := execute(t, "evidence", "list", "--repo", root, "--attempt", attempt.ID[:12])
	if strings.Count(out, "test-run") != 2 || !strings.Contains(out, "counted") || !strings.Contains(out, "stale") {
		t.Fatalf("evidence list = %q, want two records, one counted and one stale", out)
	}
}

func TestStatusSummarisesRepository(t *testing.T) {
	root, _ := seededRepo(t)
	out := execute(t, "status", "--repo", root)
	for _, want := range []string{"intents    1", "attempts   1", "evidence   2 (counted 1, stale 1, superseded 0, not independent 0)", "scope violations recorded on 1 attempt"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestStatusWithoutStoreExplainsHowToProceed(t *testing.T) {
	command := New(nil)
	command.SetOut(&strings.Builder{})
	var errOut strings.Builder
	command.SetErr(&errOut)
	command.SetArgs([]string{"status", "--repo", t.TempDir()})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "mei init") {
		t.Fatalf("error = %v, want guidance to run mei init", err)
	}
}

// addOpenAttempt opens another attempt on intent in the repo's store.
func addOpenAttempt(t *testing.T, root, intent string) error {
	t.Helper()
	backend, err := sqlite.Open(filepath.Join(root, ".meiosis", "meiosisd.db"))
	if err != nil {
		return err
	}
	defer func() { _ = backend.Close() }()
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	_, err = graph.NewStore(backend).OpenAttempt(context.Background(), graph.OpenAttemptParams{Intent: intent, Author: "agent:other"}, keys.PrivateKey)
	return err
}
