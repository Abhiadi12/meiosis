package spec

import (
	"testing"

	"github.com/mindfire-test/meiosis/internal/jsonschema"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestEveryBuiltinKindHasAUsableSchema(t *testing.T) {
	builtin := []specv1.EvidenceKind{
		specv1.EvidenceKindTestRun, specv1.EvidenceKindCoverage, specv1.EvidenceKindTypeCheck,
		specv1.EvidenceKindStaticAnalysis, specv1.EvidenceKindBenchmark, specv1.EvidenceKindMutation,
		specv1.EvidenceKindSecurityScan, specv1.EvidenceKindReplayMatch, specv1.EvidenceKindHumanReview,
	}
	if got := EvidenceSchemaKinds(); len(got) != len(builtin) {
		t.Fatalf("published schemas = %v, want one per built-in kind (%d)", got, len(builtin))
	}
	for _, kind := range builtin {
		schema, err := EvidenceSchema(kind)
		if err != nil {
			t.Fatalf("EvidenceSchema(%s): %v", kind, err)
		}
		if err := jsonschema.CheckSchema(schema); err != nil {
			t.Errorf("schema for %s is unusable: %v", kind, err)
		}
		if err := jsonschema.Validate(schema, []byte(`{}`)); err != nil {
			t.Errorf("an empty object must satisfy the %s schema: %v", kind, err)
		}
		if err := jsonschema.Validate(schema, []byte(`[1]`)); err == nil {
			t.Errorf("a non-object payload must be rejected by the %s schema", kind)
		}
	}
	if _, err := EvidenceSchema("x-custom"); err == nil {
		t.Error("EvidenceSchema accepted a custom kind")
	}
}
