package evidence

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	meiosiscrypto "github.com/mindfire-test/meiosis/pkg/crypto"
	v1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

func TestIngestGoTestJSON(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	}()
	graphStore, err := graph.New(store)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := meiosiscrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attempt := testAttempt()
	if putErr := graphStore.PutAttempt(context.Background(), attempt); putErr != nil {
		t.Fatal(putErr)
	}
	evidence, err := IngestGoTestJSON(context.Background(), graphStore, attempt.ID, "agent:ci", attempt.World, keys.PrivateKey, strings.NewReader(`{"Time":"2026-09-09T10:00:00Z","Action":"start","Package":"example"}
{"Time":"2026-09-09T10:00:01Z","Action":"pass","Package":"example","Elapsed":1}`))
	if err != nil {
		t.Fatalf("IngestGoTestJSON() error = %v", err)
	}
	if evidence.Outcome != v1.EvidenceOutcomePass || evidence.Signature == "" {
		t.Fatalf("evidence = %+v, want pass with signature", evidence)
	}
	valid, err := meiosiscrypto.Verify(evidence, evidence.Signature, keys.PublicKey)
	if err != nil || !valid {
		t.Fatalf("signature verification = %v, %v", valid, err)
	}
	if _, err := graphStore.GetEvidence(context.Background(), evidence.ID); err != nil {
		t.Fatalf("stored evidence unavailable: %v", err)
	}
}

func TestIngestGoTestJSONRejectsMalformedOutput(t *testing.T) {
	keys := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	}()
	graphStore, _ := graph.New(store)
	for name, input := range map[string]string{
		"bad JSON":       "not-json",
		"missing action": `{"Package":"example"}`,
		"empty":          "",
		"unknown action": `{"Action":"unknown"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := IngestGoTestJSON(context.Background(), graphStore, "att_missing", "agent:ci", validWorld(), keys, strings.NewReader(input)); err == nil {
				t.Fatal("IngestGoTestJSON() accepted malformed output")
			}
		})
	}
}

func TestIngestGoTestJSONRejectsInactiveAttempt(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	}()
	graphStore, _ := graph.New(store)
	attempt := testAttempt()
	attempt.Status = v1.AttemptStatusMerged
	if err := graphStore.PutAttempt(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	keys, _ := meiosiscrypto.GenerateKeyPair()
	if _, err := IngestGoTestJSON(context.Background(), graphStore, attempt.ID, "agent:ci", attempt.World, keys.PrivateKey, strings.NewReader(`{"Action":"pass"}`)); err == nil {
		t.Fatal("IngestGoTestJSON() accepted inactive attempt")
	}
}

func testAttempt() v1.Attempt {
	hash := validWorld()
	return v1.Attempt{ID: "att_" + strings.Repeat("a", 52), Intent: "int_" + strings.Repeat("b", 52), Author: "agent:planner", World: hash, BaseWorld: hash, Status: v1.AttemptStatusOpen, CreatedAt: time.Unix(1, 0), Signature: "attempt-signature"}
}

func validWorld() v1.WorldHash {
	return v1.MustParseWorldHash(strings.Repeat("a", 64))
}

func newIngestEnv(t *testing.T) (*graph.Store, v1.Attempt, ed25519.PrivateKey) {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	graphStore, err := graph.New(store)
	if err != nil {
		t.Fatal(err)
	}
	attempt := testAttempt()
	if err = graphStore.PutAttempt(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	keys, err := meiosiscrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return graphStore, attempt, keys.PrivateKey
}

func TestIngestDetectsTheFormatAndBindsTheWorld(t *testing.T) {
	store, attempt, key := newIngestEnv(t)
	ctx := context.Background()
	for file, want := range map[string]v1.EvidenceKind{
		"junit_pass.xml": v1.EvidenceKindTestRun, "sarif_clean.json": v1.EvidenceKindStaticAnalysis,
		"cobertura.xml": v1.EvidenceKindCoverage, "lcov.info": v1.EvidenceKindCoverage, "cyclonedx_vulns.json": v1.EvidenceKindSecurityScan,
	} {
		ev, report, err := Ingest(ctx, store, IngestParams{Attempt: attempt.ID, Producer: "agent:ci", World: attempt.World}, key, fixture(t, file))
		if err != nil {
			t.Fatalf("Ingest(%s): %v", file, err)
		}
		if ev.Kind != want || ev.World != attempt.World || !ev.Independent || ev.Outcome != report.Outcome {
			t.Errorf("Ingest(%s) = kind %s world %s independent %t outcome %s", file, ev.Kind, ev.World, ev.Independent, ev.Outcome)
		}
		if ok, verr := meiosiscrypto.Verify(ev, ev.Signature, key.Public().(ed25519.PublicKey)); verr != nil || !ok {
			t.Errorf("Ingest(%s): signature invalid: %v, %v", file, ok, verr)
		}
		stored, err := store.GetEvidence(ctx, ev.ID)
		if err != nil || stored.ID != ev.ID {
			t.Errorf("Ingest(%s): stored evidence unavailable: %v", file, err)
		}
	}
}

func TestIngestRefusesWhatCannotBeBoundToAWorldOrAnOpenAttempt(t *testing.T) {
	store, attempt, key := newIngestEnv(t)
	ctx := context.Background()
	junit := fixture(t, "junit_pass.xml")

	if _, _, err := Ingest(ctx, store, IngestParams{Attempt: attempt.ID, Producer: "agent:ci"}, key, junit); err == nil {
		t.Error("evidence with no world hash was accepted (FR-4.1)")
	}
	if _, _, err := Ingest(ctx, store, IngestParams{Attempt: "att_" + strings.Repeat("z", 52), Producer: "agent:ci", World: attempt.World}, key, junit); err == nil {
		t.Error("evidence for an unknown attempt was accepted")
	}
	if _, _, err := Ingest(ctx, store, IngestParams{Attempt: attempt.ID, Producer: "agent:ci", World: attempt.World}, key, []byte("garbage")); err == nil {
		t.Error("an undetectable report was accepted")
	}
	if _, _, err := Ingest(ctx, nil, IngestParams{}, key, junit); err == nil {
		t.Error("a nil store was accepted")
	}
}

func TestIngestSupersedesTheProducersEarlierRecord(t *testing.T) {
	store, attempt, key := newIngestEnv(t)
	ctx := context.Background()
	params := IngestParams{Attempt: attempt.ID, Producer: "agent:ci", World: attempt.World}

	failed, _, err := Ingest(ctx, store, params, key, fixture(t, "junit_fail.xml"))
	if err != nil {
		t.Fatal(err)
	}
	params.Supersedes = failed.ID
	fixed, _, err := Ingest(ctx, store, params, key, fixture(t, "junit_pass.xml"))
	if err != nil {
		t.Fatalf("superseding ingest: %v", err)
	}
	if fixed.Supersedes != failed.ID {
		t.Fatalf("Supersedes = %q", fixed.Supersedes)
	}
}
