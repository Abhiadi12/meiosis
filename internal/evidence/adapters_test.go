package evidence

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/jsonschema"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/spec"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func payloadOf(t *testing.T, r Report) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Payload, &m); err != nil {
		t.Fatalf("payload is not a JSON object: %v", err)
	}
	return m
}

func num(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("payload[%q] = %v (%T), want a number; payload %v", key, m[key], m[key], m)
	}
	return v
}

func mustParse(t *testing.T, format Format, name string, opts Options) Report {
	t.Helper()
	r, err := Parse(format, fixture(t, name), opts)
	if err != nil {
		t.Fatalf("Parse(%s, %s) error = %v", format, name, err)
	}
	return r
}

func TestJUnit(t *testing.T) {
	pass := mustParse(t, FormatJUnit, "junit_pass.xml", Options{})
	if pass.Outcome != specv1.EvidenceOutcomePass || pass.Kind != specv1.EvidenceKindTestRun {
		t.Fatalf("pass report = %s/%s", pass.Kind, pass.Outcome)
	}
	p := payloadOf(t, pass)
	if num(t, p, "tests") != 3 || num(t, p, "failures") != 0 || num(t, p, "duration_seconds") != 1.5 || len(p["suites"].([]any)) != 2 {
		t.Fatalf("pass payload = %v", p)
	}

	fail := mustParse(t, FormatJUnit, "junit_fail.xml", Options{})
	f := payloadOf(t, fail)
	// The suite header claims 99 tests and 0 failures; the cases are the truth.
	if fail.Outcome != specv1.EvidenceOutcomeFail || num(t, f, "tests") != 5 || num(t, f, "failures") != 2 || num(t, f, "errors") != 1 || num(t, f, "skipped") != 1 {
		t.Fatalf("fail payload = %v", f)
	}
	failed := f["failed_tests"].([]any)
	if len(failed) != 3 || failed[0].(map[string]any)["message"] != "expected 200, got 500" {
		t.Fatalf("failed_tests = %v", failed)
	}
	if got := failed[1].(map[string]any)["message"]; got != "panic: nil pointer" {
		t.Fatalf("an <error> with no message attribute should fall back to its text, got %v", got)
	}

	if r := mustParse(t, FormatJUnit, "junit_single.xml", Options{}); r.Outcome != specv1.EvidenceOutcomePass {
		t.Fatalf("single <testsuite> root outcome = %s", r.Outcome)
	}
	for _, name := range []string{"junit_empty.xml", "junit_allskipped.xml"} {
		if r := mustParse(t, FormatJUnit, name, Options{}); r.Outcome != specv1.EvidenceOutcomeInconclusive {
			t.Errorf("%s outcome = %s, want inconclusive (nothing ran)", name, r.Outcome)
		}
	}
}

func TestJUnitCapsListedFailures(t *testing.T) {
	var b strings.Builder
	b.WriteString("<testsuite name=\"s\">")
	for i := 0; i < maxFailures+30; i++ {
		b.WriteString(`<testcase name="t"><failure message="x"/></testcase>`)
	}
	b.WriteString("</testsuite>")
	r, err := Parse(FormatJUnit, []byte(b.String()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := payloadOf(t, r)
	if num(t, p, "failures") != float64(maxFailures+30) || len(p["failed_tests"].([]any)) != maxFailures {
		t.Fatalf("failures = %v, listed = %d; want the count exact and the list capped at %d", p["failures"], len(p["failed_tests"].([]any)), maxFailures)
	}
}

func TestSARIF(t *testing.T) {
	r := mustParse(t, FormatSARIF, "sarif_error.json", Options{})
	p := payloadOf(t, r)
	counts := p["counts"].(map[string]any)
	if r.Outcome != specv1.EvidenceOutcomeFail || r.Kind != specv1.EvidenceKindStaticAnalysis || num(t, p, "results") != 6 {
		t.Fatalf("report = %s/%s %v", r.Kind, r.Outcome, p)
	}
	if counts["error"] != float64(2) || counts["warning"] != float64(2) || counts["note"] != float64(2) {
		t.Fatalf("counts = %v, want a missing level read as warning and \"none\" as note", counts)
	}
	if top := p["top_rules"].([]any)[0].(map[string]any); top["rule"] != "errcheck" || top["count"] != float64(2) {
		t.Fatalf("top rule = %v", top)
	}
	if tools := p["tools"].([]any); len(tools) != 1 || tools[0] != "golangci-lint" {
		t.Fatalf("tools = %v", tools)
	}

	if r = mustParse(t, FormatSARIF, "sarif_clean.json", Options{}); r.Outcome != specv1.EvidenceOutcomePass {
		t.Fatalf("clean run outcome = %s", r.Outcome)
	}
	if r = mustParse(t, FormatSARIF, "sarif_warnings.json", Options{}); r.Outcome != specv1.EvidenceOutcomePass {
		t.Fatalf("warnings-only outcome = %s, want pass (only errors fail)", r.Outcome)
	}
	if r = mustParse(t, FormatSARIF, "sarif_norun.json", Options{}); r.Outcome != specv1.EvidenceOutcomeInconclusive {
		t.Fatalf("no-run outcome = %s", r.Outcome)
	}

	scan := mustParse(t, FormatSARIF, "sarif_error.json", Options{Kind: specv1.EvidenceKindSecurityScan})
	if scan.Kind != specv1.EvidenceKindSecurityScan {
		t.Fatalf("SARIF recorded as security-scan got kind %s", scan.Kind)
	}
}

func TestCobertura(t *testing.T) {
	r := mustParse(t, FormatCobertura, "cobertura.xml", Options{})
	p := payloadOf(t, r)
	// The root attributes claim 990/1000; the line elements say 3 of 5.
	if num(t, p, "lines_valid") != 5 || num(t, p, "lines_covered") != 3 || num(t, p, "line_rate") != 0.6 || num(t, p, "files") != 2 {
		t.Fatalf("payload = %v, want the counted lines to win over the declared totals", p)
	}
	if num(t, p, "branches_valid") != 2 || num(t, p, "branches_covered") != 1 || num(t, p, "branch_rate") != 0.5 {
		t.Fatalf("branch payload = %v", p)
	}
	if r.Outcome != specv1.EvidenceOutcomeInconclusive || r.Kind != specv1.EvidenceKindCoverage {
		t.Fatalf("without a threshold coverage is a measurement: %s/%s", r.Kind, r.Outcome)
	}

	ok, bad := 50.0, 90.0
	if r = mustParse(t, FormatCobertura, "cobertura.xml", Options{MinLineCoverage: &ok}); r.Outcome != specv1.EvidenceOutcomePass || num(t, payloadOf(t, r), "threshold_percent") != 50 {
		t.Fatalf("60%% against a 50%% bar = %s", r.Outcome)
	}
	if r = mustParse(t, FormatCobertura, "cobertura.xml", Options{MinLineCoverage: &bad}); r.Outcome != specv1.EvidenceOutcomeFail {
		t.Fatalf("60%% against a 90%% bar = %s", r.Outcome)
	}

	attrs := payloadOf(t, mustParse(t, FormatCobertura, "cobertura_attrs_only.xml", Options{}))
	if num(t, attrs, "lines_valid") != 200 || num(t, attrs, "line_rate") != 0.75 {
		t.Fatalf("attribute-only payload = %v", attrs)
	}
	if _, err := Parse(FormatCobertura, fixture(t, "cobertura_inconsistent.xml"), Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("a report with more covered than valid lines: error = %v", err)
	}
	over := 101.0
	if _, err := Parse(FormatCobertura, fixture(t, "cobertura.xml"), Options{MinLineCoverage: &over}); err == nil {
		t.Fatal("a threshold above 100 was accepted")
	}
}

func TestLCOV(t *testing.T) {
	r := mustParse(t, FormatLCOV, "lcov.info", Options{})
	p := payloadOf(t, r)
	if num(t, p, "files") != 2 || num(t, p, "lines_valid") != 13 || num(t, p, "lines_covered") != 11 || num(t, p, "branches_valid") != 4 || num(t, p, "branches_covered") != 1 {
		t.Fatalf("payload = %v", p)
	}
	if r.Outcome != specv1.EvidenceOutcomeInconclusive {
		t.Fatalf("outcome = %s", r.Outcome)
	}
	high, low := 85.0, 80.0
	if r = mustParse(t, FormatLCOV, "lcov.info", Options{MinLineCoverage: &high}); r.Outcome != specv1.EvidenceOutcomeFail {
		t.Fatalf("11/13 = 84.6%% against 85%% should fail, got %s", r.Outcome)
	}
	if r = mustParse(t, FormatLCOV, "lcov.info", Options{MinLineCoverage: &low}); r.Outcome != specv1.EvidenceOutcomePass {
		t.Fatalf("11/13 = 84.6%% against 80%% should pass, got %s", r.Outcome)
	}
}

func TestCoverageRejectsMoreCoveredBranchesThanExist(t *testing.T) {
	if _, err := Parse(FormatLCOV, []byte("SF:a\nBRF:1\nBRH:2\nend_of_record\n"), Options{}); err == nil {
		t.Fatal("LCOV with BRH > BRF accepted")
	}
	if _, err := Parse(FormatCobertura, []byte(`<coverage lines-valid="5" lines-covered="1" branches-valid="1" branches-covered="2"/>`), Options{}); err == nil {
		t.Fatal("Cobertura with more covered than valid branches accepted")
	}
}

func TestLCOVRejectsNonLCOV(t *testing.T) {
	for name, in := range map[string]string{"empty": "", "text": "hello world\n", "bad DA": "SF:a\nDA:oops\nend_of_record\n"} {
		if _, err := Parse(FormatLCOV, []byte(in), Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCycloneDX(t *testing.T) {
	r := mustParse(t, FormatCycloneDX, "cyclonedx_vulns.json", Options{})
	p := payloadOf(t, r)
	v := p["vulnerabilities"].(map[string]any)
	if r.Outcome != specv1.EvidenceOutcomeFail || r.Kind != specv1.EvidenceKindSecurityScan || num(t, p, "components") != 3 {
		t.Fatalf("report = %s/%s %v", r.Kind, r.Outcome, p)
	}
	if v["high"] != float64(1) || v["medium"] != float64(1) || v["low"] != float64(1) || v["unknown"] != float64(1) || v["critical"] != float64(0) {
		t.Fatalf("vulnerabilities = %v, want each counted at its worst rating (info as low, unrated as unknown)", v)
	}
	if r = mustParse(t, FormatCycloneDX, "cyclonedx_clean.json", Options{}); r.Outcome != specv1.EvidenceOutcomePass {
		t.Fatalf("medium-only outcome = %s", r.Outcome)
	}
	if r = mustParse(t, FormatCycloneDX, "cyclonedx_none.json", Options{}); r.Outcome != specv1.EvidenceOutcomeInconclusive {
		t.Fatalf("an SBOM with no vulnerability analysis = %s, want inconclusive", r.Outcome)
	}
	if _, err := Parse(FormatCycloneDX, []byte(`{"bomFormat":"SPDX"}`), Options{}); err == nil {
		t.Fatal("a non-CycloneDX document was accepted")
	}
}

func TestGoTest(t *testing.T) {
	pass := mustParse(t, FormatGoTest, "gotest_pass.jsonl", Options{})
	p := payloadOf(t, pass)
	if pass.Outcome != specv1.EvidenceOutcomePass || num(t, p, "tests") != 2 || num(t, p, "skipped") != 1 || num(t, p, "failures") != 0 || num(t, p, "duration_seconds") != 1.5 {
		t.Fatalf("pass = %s %v", pass.Outcome, p)
	}
	fail := mustParse(t, FormatGoTest, "gotest_fail.jsonl", Options{})
	f := payloadOf(t, fail)
	failed := f["failed_tests"].([]any)
	if fail.Outcome != specv1.EvidenceOutcomeFail || len(failed) != 1 || !strings.Contains(failed[0].(map[string]any)["message"].(string), "boom") {
		t.Fatalf("fail = %s %v", fail.Outcome, f)
	}
	if r := mustParse(t, FormatGoTest, "gotest_buildfail.jsonl", Options{}); r.Outcome != specv1.EvidenceOutcomeFail {
		t.Fatalf("build failure outcome = %s", r.Outcome)
	}
	for name, in := range map[string]string{"bad JSON": "not-json", "missing action": `{"Package":"x"}`, "empty": "", "unknown action": `{"Action":"unknown"}`} {
		if _, err := Parse(FormatGoTest, []byte(in), Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEveryAdapterPayloadSatisfiesItsKindSchema(t *testing.T) {
	min := 50.0
	for _, c := range []struct {
		format Format
		file   string
		opts   Options
	}{
		{FormatJUnit, "junit_pass.xml", Options{}}, {FormatJUnit, "junit_fail.xml", Options{}}, {FormatJUnit, "junit_empty.xml", Options{}},
		{FormatGoTest, "gotest_pass.jsonl", Options{}}, {FormatGoTest, "gotest_fail.jsonl", Options{}},
		{FormatSARIF, "sarif_error.json", Options{}}, {FormatSARIF, "sarif_clean.json", Options{}}, {FormatSARIF, "sarif_error.json", Options{Kind: specv1.EvidenceKindSecurityScan}},
		{FormatCobertura, "cobertura.xml", Options{MinLineCoverage: &min}}, {FormatCobertura, "cobertura_attrs_only.xml", Options{}},
		{FormatLCOV, "lcov.info", Options{}},
		{FormatCycloneDX, "cyclonedx_vulns.json", Options{}}, {FormatCycloneDX, "cyclonedx_none.json", Options{}},
	} {
		r := mustParse(t, c.format, c.file, c.opts)
		schema, err := spec.EvidenceSchema(r.Kind)
		if err != nil {
			t.Fatal(err)
		}
		if err := jsonschema.Validate(schema, r.Payload); err != nil {
			t.Errorf("%s payload for %s violates the %s schema: %v\n%s", c.format, c.file, r.Kind, err, r.Payload)
		}
	}
}

func TestKindOverridesAreLimitedToWhatTheFormatCanBe(t *testing.T) {
	if _, err := Parse(FormatJUnit, fixture(t, "junit_pass.xml"), Options{Kind: specv1.EvidenceKindCoverage}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("a JUnit report recorded as coverage: error = %v", err)
	}
	if _, err := Parse(FormatSARIF, fixture(t, "sarif_clean.json"), Options{Kind: specv1.EvidenceKindTestRun}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("SARIF recorded as test-run: error = %v", err)
	}
}

func TestDetect(t *testing.T) {
	for file, want := range map[string]Format{
		"junit_pass.xml": FormatJUnit, "junit_single.xml": FormatJUnit, "cobertura.xml": FormatCobertura,
		"lcov.info": FormatLCOV, "sarif_error.json": FormatSARIF, "cyclonedx_vulns.json": FormatCycloneDX,
		"gotest_pass.jsonl": FormatGoTest, "gotest_buildfail.jsonl": FormatGoTest,
	} {
		got, err := Detect(fixture(t, file))
		if err != nil || got != want {
			t.Errorf("Detect(%s) = %q, %v; want %q", file, got, err, want)
		}
	}
	if _, err := Detect(append([]byte("\xef\xbb\xbf"), fixture(t, "junit_pass.xml")...)); err != nil {
		t.Errorf("a UTF-8 BOM broke detection: %v", err)
	}
	if _, err := Detect(fixture(t, "cyclonedx.xml")); err == nil || !strings.Contains(err.Error(), "JSON encoding") {
		t.Errorf("CycloneDX XML: error = %v, want a pointer to the JSON encoding", err)
	}
	for name, in := range map[string]string{"empty": "", "prose": "hello", "unknown xml": "<foo/>", "unknown json": `{"a":1}`, "bad xml": "<a", "bad json": "{"} {
		if f, err := Detect([]byte(in)); err == nil {
			t.Errorf("Detect(%s) = %q, want an error", name, f)
		}
	}
}

func TestParseFormat(t *testing.T) {
	if f, err := ParseFormat(" JUnit "); err != nil || f != FormatJUnit {
		t.Fatalf("ParseFormat = %q, %v", f, err)
	}
	if _, err := ParseFormat("tap"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ParseFormat(tap) error = %v", err)
	}
}

func TestDeeplyNestedXMLIsRejectedNotCrashed(t *testing.T) {
	deep := strings.Repeat("<testsuite>", maxXMLDepth+5) + strings.Repeat("</testsuite>", maxXMLDepth+5)
	for _, format := range []Format{FormatJUnit, FormatCobertura} {
		if _, err := Parse(format, []byte(deep), Options{}); err == nil || !strings.Contains(err.Error(), "nested") {
			t.Errorf("%s: deeply nested XML error = %v", format, err)
		}
	}
}

type repeatReader struct{ n int }

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("EOF not expected: the reader should have been cut off")
	}
	n := min(len(p), r.n)
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	r.n -= n
	return n, nil
}

func TestReadReportEnforcesTheSizeLimit(t *testing.T) {
	if _, err := ReadReport(&repeatReader{n: MaxReportBytes + 1<<20}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized report: error = %v", err)
	}
	data, err := ReadReport(strings.NewReader("small"))
	if err != nil || string(data) != "small" {
		t.Fatalf("ReadReport = %q, %v", data, err)
	}
	if _, err := ReadReport(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
}
