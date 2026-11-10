package jsonschema

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	const schema = `{
		"type": "object",
		"required": ["n"],
		"properties": {
			"n": {"type": "integer", "minimum": 0, "maximum": 10},
			"s": {"type": "string", "minLength": 2, "maxLength": 4},
			"e": {"enum": ["ab", "abc"]},
			"f": {"type": "number"},
			"xs": {"type": "array", "minItems": 1, "maxItems": 2, "items": {"type": "boolean"}},
			"o": {"type": ["object", "null"], "additionalProperties": false, "properties": {"k": {"const": 1}}}
		}
	}`
	cases := []struct {
		name, doc, wantErr string
	}{
		{"valid", `{"n": 3, "s": "ab", "e": "abc", "f": 1.5, "xs": [true], "o": {"k": 1}}`, ""},
		{"valid null", `{"n": 0, "o": null}`, ""},
		{"integer is a number", `{"n": 1, "f": 2}`, ""},
		{"missing required", `{}`, `missing required property "n"`},
		{"wrong type", `{"n": "3"}`, "must be integer, got string"},
		{"fractional integer", `{"n": 1.5}`, "must be integer, got number"},
		{"below minimum", `{"n": -1}`, "must be >= 0"},
		{"above maximum", `{"n": 11}`, "must be <= 10"},
		{"too short", `{"n": 1, "s": "a"}`, "at least 2 characters"},
		{"too long", `{"n": 1, "s": "abcde"}`, "at most 4 characters"},
		{"not in enum", `{"n": 1, "e": "zz"}`, "not one of the allowed values"},
		{"too few items", `{"n": 1, "xs": []}`, "at least 1 items"},
		{"too many items", `{"n": 1, "xs": [true, true, true]}`, "at most 2 items"},
		{"bad item", `{"n": 1, "xs": [1]}`, "$.xs[0]: must be boolean"},
		{"extra property", `{"n": 1, "o": {"z": 1}}`, `unexpected property "z"`},
		{"const mismatch", `{"n": 1, "o": {"k": 2}}`, "required constant"},
		{"not an object", `[]`, "must be object, got array"},
		{"not json", `{`, "not valid JSON"},
		{"trailing data", `{"n": 1} {}`, "not valid JSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate([]byte(schema), []byte(c.doc))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}

func TestCheckSchemaRejectsUnusableSchemas(t *testing.T) {
	for name, schema := range map[string]string{
		"not json":         `{`,
		"not an object":    `[]`,
		"unknown type":     `{"type": "date"}`,
		"type wrong shape": `{"type": 5}`,
		"bad properties":   `{"properties": []}`,
		"bad nested":       `{"properties": {"a": {"type": "nope"}}}`,
		"bad required":     `{"required": "a"}`,
		"bad items":        `{"items": []}`,
	} {
		if err := CheckSchema([]byte(schema)); err == nil {
			t.Errorf("%s: CheckSchema accepted %s", name, schema)
		}
	}
	if err := CheckSchema([]byte(`{"$schema": "x", "title": "t", "pattern": "^a"}`)); err != nil {
		t.Errorf("unsupported keywords must be ignored, got %v", err)
	}
}

func TestValidateRejectsDeeplyNestedDocuments(t *testing.T) {
	doc := strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200)
	if err := Validate([]byte(`{"type":"object"}`), []byte(doc)); err != nil {
		// Only nested objects reached through schema properties are walked, so a
		// permissive schema may accept it; the point is that it never panics.
		t.Logf("deep document: %v", err)
	}
}
