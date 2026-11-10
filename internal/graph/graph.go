// Package graph provides typed persistence for the Meiosis object graph.
package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	v1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

func New(backend storage.Store) (*Store, error) {
	if backend == nil {
		return nil, errors.New("graph storage backend must not be nil")
	}
	return &Store{backend: backend}, nil
}

// PutAttempt stores an already-signed attempt. The first call for an ID
// writes its immutable creation record; later calls update only the separate
// mutable state snapshot (world, scope violations, status), and are refused if
// they try to change who or what the attempt is.
func (s *Store) PutAttempt(ctx context.Context, attempt v1.Attempt) error {
	if err := attempt.Validate(); err != nil {
		return fmt.Errorf("validate attempt: %w", err)
	}
	data, err := v1.Canonicalize(attempt)
	if err != nil {
		return fmt.Errorf("encode attempt: %w", err)
	}
	return s.backend.Transaction(ctx, func(tx storage.Tx) error {
		raw, getErr := tx.Get(ctx, storage.KindAttempt, attempt.ID)
		if errors.Is(getErr, storage.ErrNotFound) {
			return tx.Put(ctx, storage.KindAttempt, attempt.ID, data)
		}
		if getErr != nil {
			return getErr
		}
		var created v1.Attempt
		if err := json.Unmarshal(raw, &created); err != nil {
			return err
		}
		if created.Intent != attempt.Intent || created.Author != attempt.Author ||
			created.BaseWorld != attempt.BaseWorld || !created.CreatedAt.Equal(attempt.CreatedAt) {
			return fmt.Errorf("%w: attempt %q identity fields cannot change", ErrImmutable, attempt.ID)
		}
		return tx.Put(ctx, storage.KindAttemptState, attempt.ID, data)
	})
}

// GetAttempt returns the current view of an attempt.
func (s *Store) GetAttempt(ctx context.Context, id string) (v1.Attempt, error) {
	return loadAttempt(ctx, s.backend, id)
}

// PutEvidence persists evidence only when its referenced attempt is active.
// The attempt check and evidence write occur in one transaction.
func (s *Store) PutEvidence(ctx context.Context, evidence v1.Evidence) error {
	if err := evidence.Validate(); err != nil {
		return fmt.Errorf("validate evidence: %w", err)
	}
	data, err := v1.Canonicalize(evidence)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	return s.backend.Transaction(ctx, func(tx storage.Tx) error {
		attempt, err := loadActiveAttempt(ctx, tx, evidence.Attempt)
		if err != nil {
			return err
		}
		if err = validatePayload(ctx, tx, evidence.Kind, evidence.Payload); err != nil {
			return err
		}
		if err = checkSupersedes(ctx, tx, evidence); err != nil {
			return err
		}
		// The independence flag is derived, never trusted: a caller must not
		// be able to claim independence for evidence it produced itself.
		if want := evidence.Producer != attempt.Author; evidence.Independent != want {
			return fmt.Errorf("%w: independent = %t, but producer %q and author %q imply %t",
				ErrInvalidParams, evidence.Independent, evidence.Producer, attempt.Author, want)
		}
		return putImmutable(ctx, tx, storage.KindEvidence, evidence.ID, data)
	})
}

// loadActiveAttempt reads attemptID inside tx and requires it to exist, be
// valid and be open.
func loadActiveAttempt(ctx context.Context, tx storage.Tx, attemptID string) (v1.Attempt, error) {
	attempt, err := loadAttempt(ctx, tx, attemptID)
	if err != nil {
		return v1.Attempt{}, fmt.Errorf("load attempt %q: %w", attemptID, err)
	}
	if attempt.Status != v1.AttemptStatusOpen {
		return v1.Attempt{}, fmt.Errorf("%w: %s", ErrInactiveAttempt, attemptID)
	}
	return attempt, nil
}

func (s *Store) GetEvidence(ctx context.Context, id string) (v1.Evidence, error) {
	data, err := s.backend.Get(ctx, storage.KindEvidence, id)
	if err != nil {
		return v1.Evidence{}, err
	}
	var evidence v1.Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return v1.Evidence{}, fmt.Errorf("unmarshal evidence %q: %w", id, err)
	}
	if err := evidence.Validate(); err != nil {
		return v1.Evidence{}, fmt.Errorf("validate stored evidence %q: %w", id, err)
	}
	return evidence, nil
}
