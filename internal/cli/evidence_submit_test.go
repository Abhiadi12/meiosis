package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../evidence/testdata/"

// run executes mei with standard input and returns its output and error.
func run(input string, args ...string) (string, error) {
	command := New(nil)
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetIn(strings.NewReader(input))
	command.SetArgs(args)
	err := command.Execute()
	return output.String(), err
}

func mustRun(t *testing.T, input string, args ...string) string {
	t.Helper()
	out, err := run(input, args...)
	if err != nil {
		t.Fatalf("mei %v: %v\n%s", args, err, out)
	}
	return out
}

func submitted(t *testing.T, root string, args ...string) map[string]any {
	t.Helper()
	full := append([]string{"evidence", "submit", "--repo", root, "--producer", "human:lakin", "--format", "json"}, args...)
	var out map[string]any
	if err := json.Unmarshal([]byte(mustRun(t, "", full...)), &out); err != nil {
		t.Fatalf("submit output is not JSON: %v", err)
	}
	return out["evidence"].(map[string]any)
}

func TestEvidenceSubmitIngestsAReportAsIndependentEvidence(t *testing.T) {
	root, attempt := seededRepo(t)

	// No --attempt needed: there is exactly one open attempt.
	ev := submitted(t, root, "--from", testdata+"junit_pass.xml")
	if ev["kind"] != "test-run" || ev["outcome"] != "pass" || ev["producer"] != "human:lakin" || ev["independent"] != true {
		t.Fatalf("evidence = %v", ev)
	}
	if ev["world"] != attempt.World.String() || ev["attempt"] != attempt.ID {
		t.Fatalf("evidence must be bound to the attempt's current world: %v", ev)
	}

	text := mustRun(t, "", "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--from", testdata+"junit_fail.xml", "--attempt", attempt.ID[:12])
	for _, want := range []string{"test-run fail", "from junit", "independent of the attempt's author", "bound to world"} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}

	list := mustRun(t, "", "evidence", "list", "--repo", root, "--attempt", attempt.ID[:12])
	if strings.Count(list, "test-run") != 4 { // the two seeded records plus these two
		t.Fatalf("evidence list = %s", list)
	}
}

func TestEvidenceSubmitReadsStdinAndDetectsTheFormat(t *testing.T) {
	root, _ := seededRepo(t)
	report, err := os.ReadFile(testdata + "sarif_error.json")
	if err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, string(report), "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--from", "-", "--kind", "security-scan")
	if !strings.Contains(out, "security-scan fail (from sarif)") {
		t.Fatalf("output = %s", out)
	}
}

func TestEvidenceSubmitCoverageNeedsAStatedBarToPass(t *testing.T) {
	root, _ := seededRepo(t)
	if ev := submitted(t, root, "--from", testdata+"cobertura.xml"); ev["outcome"] != "inconclusive" {
		t.Fatalf("coverage with no threshold = %v, want inconclusive", ev["outcome"])
	}
	if ev := submitted(t, root, "--from", testdata+"cobertura.xml", "--min-line-coverage", "50"); ev["outcome"] != "pass" {
		t.Fatalf("60%% against 50%% = %v", ev["outcome"])
	}
	if ev := submitted(t, root, "--from", testdata+"cobertura.xml", "--min-line-coverage", "90"); ev["outcome"] != "fail" {
		t.Fatalf("60%% against 90%% = %v", ev["outcome"])
	}
}

func TestEvidenceSubmitSupersedesAndListShowsIt(t *testing.T) {
	root, attempt := seededRepo(t)
	failed := submitted(t, root, "--from", testdata+"junit_fail.xml")
	fixed := submitted(t, root, "--from", testdata+"junit_pass.xml", "--supersedes", failed["id"].(string)[:14])
	if fixed["supersedes"] != failed["id"] {
		t.Fatalf("fixed = %v", fixed)
	}

	list := mustRun(t, "", "evidence", "list", "--repo", root, "--attempt", attempt.ID[:12])
	if !strings.Contains(list, "superseded") {
		t.Fatalf("list should show the corrected record as superseded:\n%s", list)
	}
	show := mustRun(t, "", "attempt", "show", attempt.ID[:12], "--repo", root)
	if !strings.Contains(show, "SUPERSEDED by") {
		t.Fatalf("attempt show should flag the superseded record:\n%s", show)
	}
	status := mustRun(t, "", "status", "--repo", root)
	if !strings.Contains(status, "superseded 1") {
		t.Fatalf("status = %s", status)
	}
	if _, err := run("", "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--from", testdata+"junit_pass.xml", "--supersedes", failed["id"].(string)); err == nil || !strings.Contains(err.Error(), "already superseded") {
		t.Fatalf("superseding the same record twice = %v", err)
	}
}

func TestEvidenceSubmitRefusesBadInput(t *testing.T) {
	root, _ := seededRepo(t)
	base := []string{"evidence", "submit", "--repo", root, "--producer", "human:lakin"}
	cases := map[string][]string{
		"no source":          {},
		"missing file":       {"--from", "does-not-exist.xml"},
		"unknown format":     {"--from", testdata + "junit_pass.xml", "--report-format", "tap"},
		"wrong format":       {"--from", testdata + "junit_pass.xml", "--report-format", "sarif"},
		"kind mismatch":      {"--from", testdata + "junit_pass.xml", "--kind", "coverage"},
		"outcome with from":  {"--from", testdata + "junit_pass.xml", "--outcome", "pass"},
		"payload and from":   {"--from", testdata + "junit_pass.xml", "--payload", "x.json", "--kind", "test-run", "--outcome", "pass"},
		"payload no outcome": {"--payload", "x.json", "--kind", "test-run"},
		"bad threshold":      {"--from", testdata + "cobertura.xml", "--min-line-coverage", "150"},
		"bad world":          {"--from", testdata + "junit_pass.xml", "--world", "xyz"},
		"unknown attempt":    {"--from", testdata + "junit_pass.xml", "--attempt", "att_nope"},
		"not a report":       {"--from", "../../README.md"},
	}
	for name, extra := range cases {
		if out, err := run("", append(append([]string{}, base...), extra...)...); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
	}
}

func TestEvidenceSubmitNeedsAttemptWhenSeveralAreOpen(t *testing.T) {
	root, attempt := seededRepo(t)
	// Open a second attempt on the same intent.
	mustRun(t, "", "intent", "list", "--repo", root)
	if err := addOpenAttempt(t, root, attempt.Intent); err != nil {
		t.Fatal(err)
	}
	_, err := run("", "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--from", testdata+"junit_pass.xml")
	if err == nil || !strings.Contains(err.Error(), "pass --attempt") {
		t.Fatalf("ambiguous attempt error = %v", err)
	}
}

func TestEvidenceSubmitPayloadForCustomAndHumanReviewKinds(t *testing.T) {
	root, _ := seededRepo(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	schema := write("license.schema.json", `{"type":"object","required":["approved"],"properties":{"approved":{"type":"boolean"}}}`)

	// A custom kind must be registered first.
	if _, err := run(`{"approved":true}`, "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--kind", "x-license-check", "--outcome", "pass", "--payload", "-"); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("unregistered custom kind = %v", err)
	}
	mustRun(t, "", "evidence", "kind", "register", "x-license-check", "--repo", root, "--created-by", "human:lakin", "--schema", schema)
	if out := mustRun(t, "", "evidence", "kind", "list", "--repo", root); !strings.Contains(out, "x-license-check") || !strings.Contains(out, "custom") || !strings.Contains(out, "human-review") {
		t.Fatalf("kind list = %s", out)
	}

	ok := mustRun(t, `{"approved":true}`, "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--kind", "x-license-check", "--outcome", "pass", "--payload", "-")
	if !strings.Contains(ok, "x-license-check pass") {
		t.Fatalf("output = %s", ok)
	}
	if _, err := run(`{"approved":"yes"}`, "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--kind", "x-license-check", "--outcome", "pass", "--payload", "-"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a payload violating the registered schema = %v", err)
	}

	// A human review needs no adapter.
	review := mustRun(t, `{"reviewer":"lakin","comments":"looks right"}`, "evidence", "submit", "--repo", root, "--producer", "human:lakin", "--kind", "human-review", "--outcome", "pass", "--payload", "-")
	if !strings.Contains(review, "human-review pass") {
		t.Fatalf("output = %s", review)
	}

	// Re-registering an equivalent schema is fine; a different one is refused.
	mustRun(t, "", "evidence", "kind", "register", "x-license-check", "--repo", root, "--created-by", "human:lakin", "--schema", schema)
	other := write("other.schema.json", `{"type":"array"}`)
	if _, err := run("", "evidence", "kind", "register", "x-license-check", "--repo", root, "--created-by", "human:lakin", "--schema", other); err == nil || !strings.Contains(err.Error(), "x-license-check-v2") {
		t.Fatalf("changing a registered schema = %v", err)
	}
	if _, err := run("", "evidence", "kind", "register", "license", "--repo", root, "--schema", schema); err == nil {
		t.Fatal("a custom kind without the x- prefix was registered")
	}
}
