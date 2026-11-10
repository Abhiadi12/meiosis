package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/ucarion/jcs"
)

// Errors returned by canonicalisation; test with errors.Is.
var (
	ErrInvalidCanonicalJSON      = errors.New("invalid JSON for canonicalization")
	ErrUnsupportedCanonicalValue = errors.New("unsupported value for canonicalization")
)

// Canonicalize returns the RFC 8785 canonical JSON representation of value.
// The returned bytes are suitable as input to hashing and signing operations.
func Canonicalize(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedCanonicalValue, err)
	}
	return CanonicalizeJSON(data)
}

// CanonicalizeJSON parses JSON and returns its RFC 8785 canonical form.
func CanonicalizeJSON(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	value, err := decodeCanonicalValue(decoder)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCanonicalJSON, err)
	}
	if _, tokenErr := decoder.Token(); !errors.Is(tokenErr, io.EOF) {
		if tokenErr == nil {
			return nil, fmt.Errorf("%w: multiple JSON values", ErrInvalidCanonicalJSON)
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidCanonicalJSON, tokenErr)
	}

	normalized, err := normalizeCanonicalValue(value)
	if err != nil {
		return nil, err
	}
	canonical, err := jcs.Format(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCanonicalJSON, err)
	}
	return []byte(canonical), nil
}

func decodeCanonicalValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			key, keyErr := decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			keyString, ok := key.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, exists := object[keyString]; exists {
				return nil, fmt.Errorf("duplicate object key %q", keyString)
			}
			value, valueErr := decodeCanonicalValue(decoder)
			if valueErr != nil {
				return nil, valueErr
			}
			object[keyString] = value
		}
		_, err = decoder.Token()
		return object, err
	case json.Delim('['):
		array := make([]any, 0)
		for decoder.More() {
			value, valueErr := decodeCanonicalValue(decoder)
			if valueErr != nil {
				return nil, valueErr
			}
			array = append(array, value)
		}
		_, err = decoder.Token()
		return array, err
	default:
		return token, nil
	}
}

func normalizeCanonicalValue(value any) (any, error) {
	switch value := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseFloat(string(value), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return nil, fmt.Errorf("%w: invalid number", ErrInvalidCanonicalJSON)
		}
		if parsed == 0 {
			return float64(0), nil
		}
		return parsed, nil
	case []any:
		for index, item := range value {
			normalized, err := normalizeCanonicalValue(item)
			if err != nil {
				return nil, err
			}
			value[index] = normalized
		}
	case map[string]any:
		for key, item := range value {
			normalized, err := normalizeCanonicalValue(item)
			if err != nil {
				return nil, err
			}
			value[key] = normalized
		}
	}
	return value, nil
}
