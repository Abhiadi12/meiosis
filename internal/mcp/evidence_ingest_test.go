package mcp

import (
	"os"
	"strings"
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func report(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../evidence/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEvidenceIngestTurnsAReportIntoSignedEvidence(t *testing.T) {
	s := newTestServer(t)
	attempt := putAttempt(t, s, "agent:someone-else")

	out, errText := call(t, s, "evidence_ingest", map[string]any{"attempt": attempt.ID, "report": report(t, "junit_fail.xml")})
	if errText != "" {
		t.Fatalf("evidence_ingest: %s", errText)
	}
	ev := out["evidence"].(map[string]any)
	if out["format"] != "junit" || out["fresh"] != true || out["world"] != attempt.World.String() {
		t.Fatalf("result = %v", out)
	}
	// The outcome comes from the report: the agent cannot choose it.
	if ev["kind"] != "test-run" || ev["outcome"] != "fail" || ev["producer"] != s.Principal || ev["independent"] != true {
		t.Fatalf("evidence = %v", ev)
	}
	if ev["signature"] == "" {
		t.Fatal("ingested evidence is unsigned")
	}
}

func TestEvidenceIngestByTheAuthorIsNotIndependent(t *testing.T) {
	s := newTestServer(t)
	attempt := putAttempt(t, s, s.Principal)
	out, errText := call(t, s, "evidence_ingest", map[string]any{"attempt": attempt.ID, "report": report(t, "junit_pass.xml")})
	if errText != "" {
		t.Fatal(errText)
	}
	if out["evidence"].(map[string]any)["independent"] == true {
		t.Fatal("an agent ingesting a report about its own attempt must not produce independent evidence")
	}
}

func TestEvidenceIngestFormatsKindsAndThresholds(t *testing.T) {
	s := newTestServer(t)
	attempt := putAttempt(t, s, "agent:someone-else")
	ingest := func(args map[string]any) (map[string]any, string) {
		args["attempt"] = attempt.ID
		return call(t, s, "evidence_ingest", args)
	}

	for name, c := range map[string]struct {
		file, kind, outcome string
		extra               map[string]any
	}{
		"sarif":            {"sarif_error.json", "static-analysis", "fail", nil},
		"sarif as scan":    {"sarif_error.json", "security-scan", "fail", map[string]any{"kind": "security-scan"}},
		"cyclonedx":        {"cyclonedx_vulns.json", "security-scan", "fail", nil},
		"lcov measurement": {"lcov.info", "coverage", "inconclusive", nil},
		"lcov passing":     {"lcov.info", "coverage", "pass", map[string]any{"min_line_coverage": 80.0}},
		"gotest":           {"gotest_pass.jsonl", "test-run", "pass", map[string]any{"format": "gotest"}},
	} {
		args := map[string]any{"report": report(t, c.file)}
		for k, v := range c.extra {
			args[k] = v
		}
		out, errText := ingest(args)
		if errText != "" {
			t.Fatalf("%s: %s", name, errText)
		}
		ev := out["evidence"].(map[string]any)
		if ev["kind"] != c.kind || ev["outcome"] != c.outcome {
			t.Errorf("%s: kind/outcome = %v/%v, want %s/%s", name, ev["kind"], ev["outcome"], c.kind, c.outcome)
		}
	}
}

func TestEvidenceIngestRejectsBadRequests(t *testing.T) {
	s := newTestServer(t)
	attempt := putAttempt(t, s, "agent:someone-else")
	for name, args := range map[string]map[string]any{
		"unknown attempt": {"attempt": "att_" + strings.Repeat("z", 52), "report": report(t, "junit_pass.xml")},
		"not a report":    {"attempt": attempt.ID, "report": "just some words"},
		"empty":           {"attempt": attempt.ID, "report": ""},
		"unknown format":  {"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "format": "tap"},
		"kind mismatch":   {"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "kind": "coverage"},
		"bad world":       {"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "world": "nothex"},
		"zero world":      {"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "world": strings.Repeat("0", 64)},
	} {
		if out, errText := call(t, s, "evidence_ingest", args); errText == "" {
			t.Errorf("%s: accepted: %v", name, out)
		}
	}
}

func TestEvidenceIngestBindsToANamedWorldAndSaysItIsStale(t *testing.T) {
	s := newTestServer(t)
	attempt := putAttempt(t, s, "agent:someone-else")
	other := strings.Repeat("ab", 32)
	out, errText := call(t, s, "evidence_ingest", map[string]any{"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "world": other})
	if errText != "" {
		t.Fatal(errText)
	}
	if out["world"] != other || out["fresh"] != false {
		t.Fatalf("result = %v, want the named world and fresh=false", out)
	}
}

func TestEvidenceIngestHonoursTokensAndIntentBinding(t *testing.T) {
	s, issuer := enforcingServer(t)
	attempt := putAttempt(t, s, "agent:other-author")
	good := issueToken(t, issuer, s.Principal, attempt.Intent)
	wrong := issueToken(t, issuer, s.Principal, "int_"+strings.Repeat("e", 52))
	args := func(token any) map[string]any {
		return map[string]any{"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "capability_token": token}
	}
	if _, errText := call(t, s, "evidence_ingest", map[string]any{"attempt": attempt.ID, "report": report(t, "junit_pass.xml")}); !strings.Contains(errText, "capability_token is required") {
		t.Fatalf("no token: %q", errText)
	}
	if _, errText := call(t, s, "evidence_ingest", args(tokenArg(t, wrong))); !strings.Contains(errText, "different intent") {
		t.Fatalf("wrong-intent token: %q", errText)
	}
	if _, errText := call(t, s, "evidence_ingest", args(tokenArg(t, good))); errText != "" {
		t.Fatalf("good token: %s", errText)
	}
}

func TestEvidenceSubmitValidatesPayloadsAndSupportsSupersedingAndCustomKinds(t *testing.T) {
	s := newTestServer(t)
	attempt := putAttempt(t, s, "agent:someone-else")
	world := attempt.World.String()
	submit := func(args map[string]any) (map[string]any, string) {
		args["attempt"], args["world"] = attempt.ID, world
		return call(t, s, "evidence_submit", args)
	}

	if _, errText := submit(map[string]any{"kind": "test-run", "outcome": "pass", "payload": map[string]any{"tests": "many"}}); !strings.Contains(errText, "does not match") {
		t.Fatalf("a payload violating the test-run schema: %q", errText)
	}
	if _, errText := submit(map[string]any{"kind": "x-nope", "outcome": "pass", "payload": map[string]any{}}); !strings.Contains(errText, "not registered") {
		t.Fatalf("unregistered custom kind: %q", errText)
	}
	if _, errText := submit(map[string]any{"kind": "human-review", "outcome": "pass", "payload": map[string]any{"reviewer": "lakin"}}); errText != "" {
		t.Fatalf("human-review is a built-in kind: %s", errText)
	}

	first, errText := submit(map[string]any{"kind": "test-run", "outcome": "fail", "payload": map[string]any{"failures": 1}})
	if errText != "" {
		t.Fatal(errText)
	}
	second, errText := submit(map[string]any{"kind": "test-run", "outcome": "pass", "payload": map[string]any{"failures": 0}, "supersedes": first["id"]})
	if errText != "" {
		t.Fatalf("superseding: %s", errText)
	}
	if second["supersedes"] != first["id"] {
		t.Fatalf("second = %v", second)
	}
	status, _ := call(t, s, "attempt_status", map[string]any{"attempt": attempt.ID})
	counted := 0
	for _, e := range status["evidence"].([]any) {
		if e.(map[string]any)["counted"] == true {
			counted++
		}
	}
	// human-review + the correcting record count; the corrected failure does not.
	if counted != 2 {
		t.Fatalf("counted evidence = %d, want 2 (the superseded failure must not count)\n%v", counted, status["evidence"])
	}
}

func TestIngestedEvidenceCannotBeForgedThroughSupersede(t *testing.T) {
	// The CI principal's failure cannot be wiped out by the author's own record.
	ci := newTestServer(t)
	attempt := putAttempt(t, ci, "agent:impl")
	ci.Principal = "agent:ci"
	failure, errText := call(t, ci, "evidence_ingest", map[string]any{"attempt": attempt.ID, "report": report(t, "junit_fail.xml")})
	if errText != "" {
		t.Fatal(errText)
	}

	author := newTestServer(t)
	author.Graph = ci.Graph
	author.Principal = "agent:impl"
	_, errText = call(t, author, "evidence_ingest", map[string]any{
		"attempt": attempt.ID, "report": report(t, "junit_pass.xml"), "supersedes": failure["evidence"].(map[string]any)["id"],
	})
	if !strings.Contains(errText, "only the producer") {
		t.Fatalf("author superseding CI's failure = %q", errText)
	}
	_ = specv1.EvidenceKindTestRun
}
