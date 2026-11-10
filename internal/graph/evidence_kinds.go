package graph

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mindfire-test/meiosis/internal/jsonschema"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
	"github.com/mindfire-test/meiosis/spec"
)

var (
	// ErrUnknownKind is returned when evidence names a custom kind that was
	// never registered.
	ErrUnknownKind = errors.New("graph: evidence kind is not registered")
	// ErrPayloadInvalid is returned when an evidence payload does not satisfy
	// its kind's schema.
	ErrPayloadInvalid = errors.New("graph: evidence payload does not match its kind's schema")
)

// payloadSchema returns the schema payloads of kind must satisfy: the
// published one for a built-in kind, the registered one for a custom kind.
func payloadSchema(ctx context.Context, g getter, kind specv1.EvidenceKind) ([]byte, error) {
	if specv1.IsBuiltinEvidenceKind(kind) {
		return spec.EvidenceSchema(kind)
	}
	data, err := g.Get(ctx, storage.KindEvidenceKind, string(kind))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s (register it with `mei evidence kind register`)", ErrUnknownKind, kind)
	}
	if err != nil {
		return nil, err
	}
	var def specv1.EvidenceKindDef
	if err = json.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("graph: decode evidence kind %q: %w", kind, err)
	}
	return def.Schema, nil
}

// validatePayload checks an evidence payload against its kind's schema.
func validatePayload(ctx context.Context, g getter, kind specv1.EvidenceKind, payload json.RawMessage) error {
	schema, err := payloadSchema(ctx, g, kind)
	if err != nil {
		return err
	}
	if err = jsonschema.Validate(schema, payload); err != nil {
		return fmt.Errorf("%w: %s payload: %w", ErrPayloadInvalid, kind, err)
	}
	return nil
}

// RegisterEvidenceKind registers a custom evidence kind with its payload schema
// (FR-4.2). Registering the same kind with an equivalent schema again is a
// no-op; a different schema is refused, since evidence already stored under
// the kind must keep meaning what it meant.
func (s *Store) RegisterEvidenceKind(ctx context.Context, kind specv1.EvidenceKind, schema []byte, registeredBy string, key ed25519.PrivateKey) (specv1.EvidenceKindDef, error) {
	if !specv1.IsCustomEvidenceKind(kind) {
		return specv1.EvidenceKindDef{}, fmt.Errorf("%w: custom kinds are named %sNAME (lower-case letters, digits, hyphens), got %q", ErrInvalidParams, specv1.CustomKindPrefix, kind)
	}
	if err := jsonschema.CheckSchema(schema); err != nil {
		return specv1.EvidenceKindDef{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	canonicalSchema, err := specv1.CanonicalizeJSON(schema)
	if err != nil {
		return specv1.EvidenceKindDef{}, fmt.Errorf("%w: schema: %w", ErrInvalidParams, err)
	}

	def := specv1.EvidenceKindDef{Kind: kind, Schema: canonicalSchema, RegisteredBy: registeredBy, RegisteredAt: time.Now().UTC()}
	signature, err := crypto.Sign(def, key)
	if err != nil {
		return specv1.EvidenceKindDef{}, fmt.Errorf("graph: sign evidence kind: %w", err)
	}
	def.Signature = signature
	if err = def.Validate(); err != nil {
		return specv1.EvidenceKindDef{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	encoded, err := specv1.Canonicalize(def)
	if err != nil {
		return specv1.EvidenceKindDef{}, fmt.Errorf("graph: encode evidence kind: %w", err)
	}

	var result specv1.EvidenceKindDef
	err = s.backend.Transaction(ctx, func(tx storage.Tx) error {
		existing, getErr := tx.Get(ctx, storage.KindEvidenceKind, string(kind))
		if errors.Is(getErr, storage.ErrNotFound) {
			result = def
			return tx.Put(ctx, storage.KindEvidenceKind, string(kind), encoded)
		}
		if getErr != nil {
			return getErr
		}
		var current specv1.EvidenceKindDef
		if err = json.Unmarshal(existing, &current); err != nil {
			return err
		}
		if !bytes.Equal(current.Schema, canonicalSchema) {
			return fmt.Errorf("%w: kind %s is already registered with a different schema; register a new name such as %s-v2", ErrImmutable, kind, kind)
		}
		result = current
		return nil
	})
	if err != nil {
		return specv1.EvidenceKindDef{}, err
	}
	return result, nil
}

// ListEvidenceKinds returns the registered custom kinds, sorted by name.
func (s *Store) ListEvidenceKinds(ctx context.Context) ([]specv1.EvidenceKindDef, error) {
	records, err := s.backend.List(ctx, storage.KindEvidenceKind)
	if err != nil {
		return nil, fmt.Errorf("graph: list evidence kinds: %w", err)
	}
	defs := make([]specv1.EvidenceKindDef, 0, len(records))
	for name, data := range records {
		var def specv1.EvidenceKindDef
		if err := json.Unmarshal(data, &def); err != nil {
			return nil, fmt.Errorf("graph: decode evidence kind %q: %w", name, err)
		}
		defs = append(defs, def)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Kind < defs[j].Kind })
	return defs, nil
}
