package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mindfire-test/meiosis/pkg/storage"
)

// IdempotentRecord is what is remembered about a call made with an idempotency key.
type IdempotentRecord struct {
	// Digest identifies the request, excluding credentials and the key.
	Digest string          `json:"digest"`
	Result json.RawMessage `json:"result"`
	At     time.Time       `json:"at"`
}

// GetIdempotent returns the remembered result for id, if any.
func (s *Store) GetIdempotent(ctx context.Context, id string) (IdempotentRecord, bool, error) {
	data, err := s.backend.Get(ctx, storage.KindIdempotency, id)
	if errors.Is(err, storage.ErrNotFound) {
		return IdempotentRecord{}, false, nil
	}
	if err != nil {
		return IdempotentRecord{}, false, err
	}
	var rec IdempotentRecord
	if err = json.Unmarshal(data, &rec); err != nil {
		return IdempotentRecord{}, false, fmt.Errorf("graph: decode idempotency record: %w", err)
	}
	return rec, true, nil
}

// PutIdempotent remembers the result of a call. A key, once used, keeps its
// first result.
func (s *Store) PutIdempotent(ctx context.Context, id, digest string, result json.RawMessage) error {
	data, err := json.Marshal(IdempotentRecord{Digest: digest, Result: result, At: time.Now().UTC()})
	if err != nil {
		return err
	}
	return s.backend.Transaction(ctx, func(tx storage.Tx) error {
		if _, getErr := tx.Get(ctx, storage.KindIdempotency, id); getErr == nil {
			return nil
		} else if !errors.Is(getErr, storage.ErrNotFound) {
			return getErr
		}
		return tx.Put(ctx, storage.KindIdempotency, id, data)
	})
}
