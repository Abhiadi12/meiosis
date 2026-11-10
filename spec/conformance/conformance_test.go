// Package conformance runs the language-agnostic fixtures and known-answer
// vectors in this directory against the Go implementation of spec/v1. Other
// implementations consume the same JSON files; see README.md.
package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestValidFixtures(t *testing.T) {
	for _, objectType := range objectTypes() {
		for _, path := range fixturePaths(t, objectType, "valid") {
			t.Run(filepath.ToSlash(path), func(t *testing.T) {
				value, err := decodeFixture(objectType, path)
				if err != nil {
					t.Fatalf("decode fixture: %v", err)
				}
				if err := value.validate(); err != nil {
					t.Fatalf("valid fixture rejected: %v", err)
				}
			})
		}
	}
}

func TestInvalidFixtures(t *testing.T) {
	for _, objectType := range objectTypes() {
		for _, path := range fixturePaths(t, objectType, "invalid") {
			t.Run(filepath.ToSlash(path), func(t *testing.T) {
				value, err := decodeFixture(objectType, path)
				if err == nil {
					err = value.validate()
				}
				if err == nil {
					t.Fatal("invalid fixture was accepted")
				}
			})
		}
	}
}

type fixtureValue struct {
	value    any
	validate func() error
}

func objectTypes() []string {
	return []string{"principal", "intent", "intent-state", "attempt", "world-hash", "evidence", "evidence-kind", "capability-token", "authority-record", "ref-update", "operation", "attestation", "verdict"}
}

func fixturePaths(t *testing.T, objectType, validity string) []string {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate conformance fixtures")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(source), objectType, validity, "*.json"))
	if err != nil {
		t.Fatalf("find fixtures: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no %s fixtures for %s", validity, objectType)
	}
	return paths
}

func decodeFixture(objectType, path string) (fixtureValue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fixtureValue{}, err
	}
	value := fixtureValue{}
	switch objectType {
	case "principal":
		var v specv1.Principal
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "intent":
		var v specv1.Intent
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "intent-state":
		var v specv1.IntentState
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "attempt":
		var v specv1.Attempt
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "world-hash":
		var v specv1.WorldHash
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "evidence":
		var v specv1.Evidence
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "evidence-kind":
		var v specv1.EvidenceKindDef
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "operation":
		var v specv1.Operation
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "ref-update":
		var v specv1.RefUpdate
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "capability-token":
		var v specv1.CapabilityToken
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "authority-record":
		var v specv1.AuthorityRecord
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "attestation":
		var v specv1.Attestation
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	case "verdict":
		var v specv1.Verdict
		err = json.Unmarshal(data, &v)
		value.value, value.validate = v, v.Validate
	default:
		return fixtureValue{}, os.ErrInvalid
	}
	return value, err
}
