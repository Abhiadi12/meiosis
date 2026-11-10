package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

var (
	// ErrUnknownEvidence is returned when a record to supersede does not exist.
	ErrUnknownEvidence = errors.New("graph: unknown evidence")
	// ErrEvidenceSuperseded is returned when a record already has a successor.
	ErrEvidenceSuperseded = errors.New("graph: evidence is already superseded")
	// ErrSupersedeNotProducer is returned when someone other than a record's
	// producer tries to correct it.
	ErrSupersedeNotProducer = errors.New("graph: only the producer of a record may supersede it")
)

// checkSupersedes enforces FR-4.12 for evidence that corrects an earlier
// record: the earlier record must exist, concern the same attempt, belong to
// the same producer, and not already have a successor. The earlier record is
// never touched; it stops counting because a newer one points at it.
//
// Restricting corrections to the original producer matters: otherwise an agent
// could "correct" an independent CI failure with its own passing record and
// make the failure stop counting.
func checkSupersedes(ctx context.Context, tx storage.Tx, ev specv1.Evidence) error {
	if ev.Supersedes == "" {
		return nil
	}
	data, err := tx.Get(ctx, storage.KindEvidence, ev.Supersedes)
	if errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("%w: %s", ErrUnknownEvidence, ev.Supersedes)
	}
	if err != nil {
		return err
	}
	var old specv1.Evidence
	if err = json.Unmarshal(data, &old); err != nil {
		return fmt.Errorf("graph: decode evidence %q: %w", ev.Supersedes, err)
	}
	if old.Attempt != ev.Attempt {
		return fmt.Errorf("%w: %s belongs to attempt %s, not %s", ErrInvalidParams, old.ID, old.Attempt, ev.Attempt)
	}
	if old.Producer != ev.Producer {
		return fmt.Errorf("%w: %s was produced by %s, not %s", ErrSupersedeNotProducer, old.ID, old.Producer, ev.Producer)
	}

	all, err := tx.List(ctx, storage.KindEvidence)
	if err != nil {
		return err
	}
	for id, raw := range all {
		if id == ev.ID {
			continue // re-storing this very record is idempotent
		}
		var other specv1.Evidence
		if err = json.Unmarshal(raw, &other); err != nil {
			return fmt.Errorf("graph: decode evidence %q: %w", id, err)
		}
		if other.Supersedes == old.ID {
			return fmt.Errorf("%w: %s is superseded by %s", ErrEvidenceSuperseded, old.ID, other.ID)
		}
	}
	return nil
}

// SupersededBy maps each superseded evidence ID to the record that replaced it.
func SupersededBy(records []specv1.Evidence) map[string]string {
	out := map[string]string{}
	for _, e := range records {
		if e.Supersedes != "" {
			out[e.Supersedes] = e.ID
		}
	}
	return out
}
