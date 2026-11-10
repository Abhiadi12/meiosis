// Package jsonschema validates JSON documents against a small, dependency-free
// subset of JSON Schema (2020-12): enough to publish and enforce a payload
// schema per evidence kind (FR-4.2) without adding a module to the dependency
// budget (SRS §3.3).
//
// Supported keywords: type (a name or a list), properties, required,
// additionalProperties (boolean), items, minItems, maxItems, enum, const,
// minimum, maximum, minLength, maxLength. Other keywords ($schema, title,
// description, ...) are accepted and ignored, so a schema authored for a full
// validator still loads; it is simply checked less strictly.
package jsonschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrInvalidSchema is returned when a schema document is not a usable schema.
var ErrInvalidSchema = errors.New("jsonschema: invalid schema")

// Error is a validation failure at a JSON path.
type Error struct {
	Path    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Path, e.Message) }

const maxDepth = 64

// CheckSchema reports whether schema is a JSON object this package can use.
func CheckSchema(schema []byte) error {
	doc, err := decode(schema)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSchema, err)
	}
	return checkSchemaNode(doc, 0)
}

func checkSchemaNode(node any, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: nested too deeply", ErrInvalidSchema)
	}
	m, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: a schema must be an object", ErrInvalidSchema)
	}
	if t, present := m["type"]; present {
		names := typeNames(t)
		if len(names) == 0 {
			return fmt.Errorf("%w: type must be a name or a list of names", ErrInvalidSchema)
		}
		for _, n := range names {
			switch n {
			case "object", "array", "string", "number", "integer", "boolean", "null":
			default:
				return fmt.Errorf("%w: unknown type %q", ErrInvalidSchema, n)
			}
		}
	}
	if props, present := m["properties"]; present {
		pm, ok := props.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: properties must be an object", ErrInvalidSchema)
		}
		for _, sub := range pm {
			if err := checkSchemaNode(sub, depth+1); err != nil {
				return err
			}
		}
	}
	if items, present := m["items"]; present {
		if err := checkSchemaNode(items, depth+1); err != nil {
			return err
		}
	}
	if req, present := m["required"]; present {
		list, ok := req.([]any)
		if !ok {
			return fmt.Errorf("%w: required must be a list", ErrInvalidSchema)
		}
		for _, r := range list {
			if _, ok := r.(string); !ok {
				return fmt.Errorf("%w: required entries must be strings", ErrInvalidSchema)
			}
		}
	}
	return nil
}

// Validate checks document against schema and returns the first violation, or
// nil. Both are JSON text.
func Validate(schema, document []byte) error {
	if err := CheckSchema(schema); err != nil {
		return err
	}
	s, _ := decode(schema)
	d, err := decode(document)
	if err != nil {
		return &Error{Path: "$", Message: "not valid JSON: " + err.Error()}
	}
	schemaObject, ok := s.(map[string]any)
	if !ok {
		return &Error{Path: "$", Message: "the schema must be a JSON object"}
	}
	return validate(schemaObject, d, "$", 0)
}

func decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

func typeNames(t any) []string {
	switch v := t.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

func jsonType(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if isInteger(x) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func isInteger(n json.Number) bool {
	r, ok := new(big.Rat).SetString(n.String())
	return ok && r.IsInt()
}

func matchesType(v any, name string) bool {
	t := jsonType(v)
	return t == name || (name == "number" && t == "integer")
}

func validate(schema map[string]any, v any, path string, depth int) error {
	if depth > maxDepth {
		return &Error{Path: path, Message: "document is nested too deeply"}
	}
	if t, ok := schema["type"]; ok {
		names := typeNames(t)
		matched := false
		for _, n := range names {
			if matchesType(v, n) {
				matched = true
				break
			}
		}
		if !matched {
			return &Error{Path: path, Message: fmt.Sprintf("must be %s, got %s", joinOr(names), jsonType(v))}
		}
	}
	if c, ok := schema["const"]; ok && !equal(c, v) {
		return &Error{Path: path, Message: "must equal the required constant"}
	}
	if e, ok := schema["enum"].([]any); ok {
		found := false
		for _, option := range e {
			if equal(option, v) {
				found = true
				break
			}
		}
		if !found {
			return &Error{Path: path, Message: "is not one of the allowed values"}
		}
	}

	switch x := v.(type) {
	case json.Number:
		if err := checkBound(schema, "minimum", x, path, func(c int) bool { return c >= 0 }, "must be >= "); err != nil {
			return err
		}
		if err := checkBound(schema, "maximum", x, path, func(c int) bool { return c <= 0 }, "must be <= "); err != nil {
			return err
		}
	case string:
		n := utf8.RuneCountInString(x)
		if m, ok := intKeyword(schema, "minLength"); ok && n < m {
			return &Error{Path: path, Message: fmt.Sprintf("must be at least %d characters", m)}
		}
		if m, ok := intKeyword(schema, "maxLength"); ok && n > m {
			return &Error{Path: path, Message: fmt.Sprintf("must be at most %d characters", m)}
		}
	case []any:
		if m, ok := intKeyword(schema, "minItems"); ok && len(x) < m {
			return &Error{Path: path, Message: fmt.Sprintf("must have at least %d items", m)}
		}
		if m, ok := intKeyword(schema, "maxItems"); ok && len(x) > m {
			return &Error{Path: path, Message: fmt.Sprintf("must have at most %d items", m)}
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, el := range x {
				if err := validate(items, el, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, present := x[name]; !present {
					return &Error{Path: path, Message: fmt.Sprintf("is missing required property %q", name)}
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			sub, known := props[k].(map[string]any)
			if known {
				if err := validate(sub, x[k], path+"."+k, depth+1); err != nil {
					return err
				}
			} else if allow, ok := schema["additionalProperties"].(bool); ok && !allow {
				return &Error{Path: path, Message: fmt.Sprintf("has unexpected property %q", k)}
			}
		}
	}
	return nil
}

func joinOr(names []string) string {
	switch len(names) {
	case 0:
		return "a valid value"
	case 1:
		return names[0]
	}
	out := names[0]
	var outSb276 strings.Builder
	for _, n := range names[1:] {
		outSb276.WriteString(" or " + n)
	}
	out += outSb276.String()
	return out
}

func intKeyword(schema map[string]any, key string) (int, bool) {
	n, ok := schema[key].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil || i < 0 {
		return 0, false
	}
	return int(i), true
}

func checkBound(schema map[string]any, key string, v json.Number, path string, ok func(int) bool, msg string) error {
	bound, present := schema[key].(json.Number)
	if !present {
		return nil
	}
	a, okA := new(big.Rat).SetString(v.String())
	b, okB := new(big.Rat).SetString(bound.String())
	if !okA || !okB {
		return nil
	}
	if !ok(a.Cmp(b)) {
		return &Error{Path: path, Message: msg + bound.String()}
	}
	return nil
}

func equal(a, b any) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	// Compare as canonical numbers/strings: json.Number round-trips verbatim,
	// which is sufficient for the enum/const values schemas use.
	return bytes.Equal(ab, bb)
}
