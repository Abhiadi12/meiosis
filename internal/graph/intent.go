package graph

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// ErrInvalidParams is returned when a built record fails validation before
// it would otherwise be persisted.
var ErrInvalidParams = errors.New("graph: invalid parameters")

// NewStore returns a Store persisting through backend. It is equivalent to
// New, save for the nil check, and exists for callers (the MCP daemon,
// issue #16) built against that constructor name.
func NewStore(backend storage.Store) *Store {
	return &Store{backend: backend}
}

// CreateIntentParams describes the intent being declared.
type CreateIntentParams struct {
	Repo        string
	Title       string
	Goal        string
	Acceptance  []specv1.Criterion
	NonGoals    []string
	Scope       specv1.Scope
	ContextPins []specv1.ContextPin
	Parent      string   // optional IntentID of the parent intent
	DependsOn   []string // IntentIDs this intent depends on
	CreatedBy   string   // principal declaring the intent
}

// CreateIntent builds, signs, persists and returns a new Intent. Its ID is
// content-derived (specv1.NewContentID) so identical declarations collide
// onto the same ID rather than minting duplicates. Every referenced parent and
// dependency must already exist.
func (s *Store) CreateIntent(ctx context.Context, p CreateIntentParams, signerKey ed25519.PrivateKey) (specv1.Intent, error) {
	var intent specv1.Intent
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		var err error
		intent, err = createIntentTx(ctx, tx, p, signerKey, "")
		return err
	})
	if err != nil {
		return specv1.Intent{}, err
	}
	return intent, nil
}

// createIntentTx creates the intent inside tx. supersedes, when set, is the
// predecessor this intent replaces: the new intent may not (transitively)
// depend on it, since that would make it depend on itself (FR-3.7).
func createIntentTx(ctx context.Context, tx storage.Tx, p CreateIntentParams, signerKey ed25519.PrivateKey, supersedes string) (specv1.Intent, error) {
	deps := sortedUnique(p.DependsOn)
	intent := specv1.Intent{
		Repo:        p.Repo,
		Title:       p.Title,
		Goal:        p.Goal,
		Acceptance:  p.Acceptance,
		NonGoals:    p.NonGoals,
		Scope:       p.Scope,
		ContextPins: p.ContextPins,
		Parent:      p.Parent,
		DependsOn:   deps,
		CreatedBy:   p.CreatedBy,
		CreatedAt:   time.Now().UTC(),
		Status:      specv1.IntentStatusOpen,
	}

	id, err := specv1.NewContentID("int_", intent)
	if err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: generate intent id: %w", err)
	}
	intent.ID = id

	signature, err := crypto.Sign(intent, signerKey)
	if err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: sign intent: %w", err)
	}
	intent.Signature = signature

	if validateErr := intent.Validate(); validateErr != nil {
		return specv1.Intent{}, fmt.Errorf("%w: %w", ErrInvalidParams, validateErr)
	}
	if err = checkLinks(ctx, tx, intent, supersedes); err != nil {
		return specv1.Intent{}, err
	}

	encoded, err := specv1.Canonicalize(intent)
	if err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: encode intent: %w", err)
	}
	if err = putImmutable(ctx, tx, storage.KindIntent, intent.ID, encoded); err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: persist intent: %w", err)
	}
	return intent, nil
}

// GetIntent returns the intent with the given ID.
func (s *Store) GetIntent(ctx context.Context, id string) (specv1.Intent, error) {
	data, err := s.backend.Get(ctx, storage.KindIntent, id)
	if err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: get intent: %w", err)
	}
	var intent specv1.Intent
	if err := json.Unmarshal(data, &intent); err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: decode intent: %w", err)
	}
	return intent, nil
}

// ListIntents returns every persisted intent, in no particular order.
func (s *Store) ListIntents(ctx context.Context) ([]specv1.Intent, error) {
	records, err := s.backend.List(ctx, storage.KindIntent)
	if err != nil {
		return nil, fmt.Errorf("graph: list intents: %w", err)
	}
	intents := make([]specv1.Intent, 0, len(records))
	for _, data := range records {
		var intent specv1.Intent
		if err := json.Unmarshal(data, &intent); err != nil {
			return nil, fmt.Errorf("graph: decode intent: %w", err)
		}
		intents = append(intents, intent)
	}
	return intents, nil
}

// SubmitEvidenceParams describes the evidence being submitted. The referenced
// attempt must exist and be open; Independent is derived from Producer and the
// attempt's author, not supplied.
type SubmitEvidenceParams struct {
	Attempt   string
	Producer  string
	World     specv1.WorldHash
	Kind      specv1.EvidenceKind
	Outcome   specv1.EvidenceOutcome
	Payload   json.RawMessage
	Footprint []string
	ExpiresAt time.Time
	// Supersedes names an earlier record by the same producer, on the same
	// attempt, that this one corrects (FR-4.12).
	Supersedes string
}

// SubmitEvidence builds, signs, persists and returns a new Evidence record.
// The attempt check, independence computation and write happen in one
// transaction (FR-4.1, FR-4.4).
func (s *Store) SubmitEvidence(ctx context.Context, p SubmitEvidenceParams, signerKey ed25519.PrivateKey) (specv1.Evidence, error) {
	// Every submit path (MCP evidence_submit and evidence_ingest, mei evidence
	// submit) ends here, so this is the one place footprints are checked. It
	// runs before signing: the signed bytes carry the normalised footprint.
	footprint, fpErr := specv1.ParseFootprint(p.Footprint)
	if fpErr != nil {
		return specv1.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidParams, fpErr)
	}
	evidence := specv1.Evidence{
		Attempt:    p.Attempt,
		World:      p.World,
		Kind:       p.Kind,
		Producer:   p.Producer,
		Outcome:    p.Outcome,
		Footprint:  footprint,
		Payload:    p.Payload,
		ExpiresAt:  p.ExpiresAt,
		Supersedes: p.Supersedes,
		CreatedAt:  time.Now().UTC(),
	}

	// Reject malformed input before touching storage. ID and signature are
	// filled in below, so stand-ins satisfy Validate here.
	preflight := evidence
	preflight.ID, preflight.Signature = "pending", "pending"
	if err := preflight.Validate(); err != nil {
		return specv1.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}

	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		attempt, err := loadActiveAttempt(ctx, tx, p.Attempt)
		if err != nil {
			return err
		}
		evidence.Independent = evidence.Producer != attempt.Author
		if err = validatePayload(ctx, tx, evidence.Kind, evidence.Payload); err != nil {
			return err
		}
		if err = checkSupersedes(ctx, tx, evidence); err != nil {
			return err
		}

		// Evidence.ID has no mandated format (spec/v1/evidence.md just calls
		// it a "unique identifier"), but a content-derived ID keeps it
		// consistent with Intent's scheme.
		id, err := specv1.NewContentID("evd_", evidence)
		if err != nil {
			return fmt.Errorf("graph: generate evidence id: %w", err)
		}
		evidence.ID = id

		signature, err := crypto.Sign(evidence, signerKey)
		if err != nil {
			return fmt.Errorf("graph: sign evidence: %w", err)
		}
		evidence.Signature = signature

		if validateErr := evidence.Validate(); validateErr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidParams, validateErr)
		}
		encoded, err := specv1.Canonicalize(evidence)
		if err != nil {
			return fmt.Errorf("graph: encode evidence: %w", err)
		}
		if err := putImmutable(ctx, tx, storage.KindEvidence, evidence.ID, encoded); err != nil {
			return fmt.Errorf("graph: persist evidence: %w", err)
		}
		return nil
	})
	if err != nil {
		return specv1.Evidence{}, err
	}
	return evidence, nil
}
