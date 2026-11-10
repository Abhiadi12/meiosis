package evidence

import (
	"encoding/json"
	"testing"

	"github.com/mindfire-test/meiosis/internal/jsonschema"
	"github.com/mindfire-test/meiosis/spec"
)

// FuzzParse feeds arbitrary bytes to every adapter and to format detection
// (SRS §11.1: fuzzing on all wire parsers). The property: parsing never
// panics, and whenever it succeeds the payload is a JSON object that satisfies
// its kind's published schema with an outcome the spec allows.
func FuzzParse(f *testing.F) {
	for _, name := range []string{
		"junit_pass.xml", "junit_fail.xml", "junit_single.xml", "junit_empty.xml", "sarif_error.json", "sarif_clean.json",
		"cobertura.xml", "cobertura_attrs_only.xml", "lcov.info", "cyclonedx_vulns.json", "cyclonedx_none.json",
		"gotest_pass.jsonl", "gotest_fail.jsonl", "gotest_buildfail.jsonl",
	} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte(""))
	f.Add([]byte("<"))
	f.Add([]byte(`{"runs":[{"results":[{"level":null}]}],"version":"2.1.0"}`))

	threshold := 75.0
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Detect(data)
		for _, format := range Formats() {
			report, err := Parse(format, data, Options{MinLineCoverage: &threshold})
			if err != nil {
				continue
			}
			var payload map[string]any
			if err = json.Unmarshal(report.Payload, &payload); err != nil {
				t.Fatalf("%s: payload is not a JSON object: %v", format, err)
			}
			schema, err := spec.EvidenceSchema(report.Kind)
			if err != nil {
				t.Fatalf("%s: no schema for kind %s: %v", format, report.Kind, err)
			}
			if err := jsonschema.Validate(schema, report.Payload); err != nil {
				t.Fatalf("%s: payload violates the %s schema: %v\n%s", format, report.Kind, err, report.Payload)
			}
			switch report.Outcome {
			case "pass", "fail", "inconclusive":
			default:
				t.Fatalf("%s: outcome %q is not a spec outcome", format, report.Outcome)
			}
		}
	})
}
