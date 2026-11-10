// Package spec publishes the machine-readable parts of the spec/v1 format that
// the reference implementation enforces: the JSON Schema for each built-in
// evidence kind's payload (FR-4.2).
package spec

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

//go:embed v1/schemas/*.schema.json
var schemas embed.FS

// EvidenceSchema returns the payload schema of a built-in evidence kind.
func EvidenceSchema(kind specv1.EvidenceKind) ([]byte, error) {
	if !specv1.IsBuiltinEvidenceKind(kind) {
		return nil, fmt.Errorf("spec: %q is not a built-in evidence kind", kind)
	}
	return schemas.ReadFile("v1/schemas/" + string(kind) + ".schema.json")
}

// EvidenceSchemaKinds lists the kinds that have a published schema, sorted.
func EvidenceSchemaKinds() []specv1.EvidenceKind {
	entries, _ := schemas.ReadDir("v1/schemas")
	kinds := make([]specv1.EvidenceKind, 0, len(entries))
	for _, e := range entries {
		kinds = append(kinds, specv1.EvidenceKind(strings.TrimSuffix(e.Name(), ".schema.json")))
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}
