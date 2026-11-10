package graph

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// ErrImmutable is returned when a write would change an object that the spec
// declares immutable (spec/v1 README §3.1): intents, attempts, evidence,
// attestations and verdicts are append-only once signed.
var ErrImmutable = errors.New("graph: object is immutable once stored")

// getter is the read half shared by storage.Store and storage.Tx.
type getter interface {
	Get(ctx context.Context, kind storage.Kind, key string) ([]byte, error)
}

// putImmutable stores data under kind/key only if nothing is there yet.
// Re-storing identical bytes is a no-op (idempotent); storing different bytes
// under an existing key is refused with ErrImmutable.
func putImmutable(ctx context.Context, tx storage.Tx, kind storage.Kind, key string, data []byte) error {
	existing, err := tx.Get(ctx, kind, key)
	switch {
	case err == nil:
		if bytes.Equal(existing, data) {
			return nil
		}
		return fmt.Errorf("%w: %s %q", ErrImmutable, kind, key)
	case errors.Is(err, storage.ErrNotFound):
		return tx.Put(ctx, kind, key, data)
	default:
		return err
	}
}

// loadAttempt returns the current view of an attempt: its latest state
// snapshot if it has one, otherwise its immutable creation record.
func loadAttempt(ctx context.Context, g getter, id string) (specv1.Attempt, error) {
	data, err := g.Get(ctx, storage.KindAttemptState, id)
	if errors.Is(err, storage.ErrNotFound) {
		data, err = g.Get(ctx, storage.KindAttempt, id)
	}
	if err != nil {
		return specv1.Attempt{}, err
	}
	var attempt specv1.Attempt
	if err := json.Unmarshal(data, &attempt); err != nil {
		return specv1.Attempt{}, fmt.Errorf("unmarshal attempt %q: %w", id, err)
	}
	if err := attempt.Validate(); err != nil {
		return specv1.Attempt{}, fmt.Errorf("validate stored attempt %q: %w", id, err)
	}
	return attempt, nil
}

// putAttemptCreation signs attempt and stores it as the attempt's immutable
// creation record.
func putAttemptCreation(ctx context.Context, tx storage.Tx, attempt *specv1.Attempt, key ed25519.PrivateKey) error {
	encoded, err := signAttempt(attempt, key)
	if err != nil {
		return err
	}
	return putImmutable(ctx, tx, storage.KindAttempt, attempt.ID, encoded)
}

// putAttemptState signs attempt and stores it as its new current state. The
// creation record is untouched; only the separate, mutable state snapshot
// changes (SRS §4.4). The fields that identify the attempt must match the
// creation record.
func putAttemptState(ctx context.Context, tx storage.Tx, attempt *specv1.Attempt, key ed25519.PrivateKey) error {
	data, err := tx.Get(ctx, storage.KindAttempt, attempt.ID)
	if err != nil {
		return fmt.Errorf("load attempt %q: %w", attempt.ID, err)
	}
	var created specv1.Attempt
	if err = json.Unmarshal(data, &created); err != nil {
		return fmt.Errorf("unmarshal attempt %q: %w", attempt.ID, err)
	}
	if created.Intent != attempt.Intent || created.Author != attempt.Author ||
		created.BaseWorld != attempt.BaseWorld || !created.CreatedAt.Equal(attempt.CreatedAt) {
		return fmt.Errorf("%w: attempt %q identity fields cannot change", ErrImmutable, attempt.ID)
	}
	encoded, err := signAttempt(attempt, key)
	if err != nil {
		return err
	}
	if err := tx.Put(ctx, storage.KindAttemptState, attempt.ID, encoded); err != nil {
		return fmt.Errorf("graph: persist attempt state: %w", err)
	}
	return nil
}

func signAttempt(attempt *specv1.Attempt, key ed25519.PrivateKey) ([]byte, error) {
	signature, err := crypto.Sign(*attempt, key)
	if err != nil {
		return nil, fmt.Errorf("graph: sign attempt: %w", err)
	}
	attempt.Signature = signature
	if err = attempt.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	encoded, err := specv1.Canonicalize(*attempt)
	if err != nil {
		return nil, fmt.Errorf("graph: encode attempt: %w", err)
	}
	return encoded, nil
}
