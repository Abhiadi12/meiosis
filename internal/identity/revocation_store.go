package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mindfire-test/meiosis/pkg/storage"
)

// StoreRevocationList is a RevocationChecker persisted in a storage.Store, so
// a revocation survives restarts and is visible to every process sharing the
// database (e.g. the CLI revoking while the daemon serves). Each check reads
// the store, so a revocation takes effect on the next call.
type StoreRevocationList struct {
	backend storage.Store
}

// NewStoreRevocationList returns a revocation list persisted in backend.
func NewStoreRevocationList(backend storage.Store) *StoreRevocationList {
	return &StoreRevocationList{backend: backend}
}

type revocationRecord struct {
	TokenID   string    `json:"token_id"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Revoke durably marks tokenID as revoked. Idempotent: the first revocation
// time is kept.
func (l *StoreRevocationList) Revoke(ctx context.Context, tokenID string) error {
	if !strings.HasPrefix(tokenID, "cap_") {
		return fmt.Errorf("%w: %q is not a capability token id", ErrInvalidParams, tokenID)
	}
	return l.backend.Transaction(ctx, func(tx storage.Tx) error {
		if _, err := tx.Get(ctx, storage.KindRevocation, tokenID); err == nil {
			return nil
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		data, err := json.Marshal(revocationRecord{TokenID: tokenID, RevokedAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		return tx.Put(ctx, storage.KindRevocation, tokenID, data)
	})
}

// IsRevoked reports whether tokenID has been revoked. It fails closed: if the
// store cannot be read, the token is treated as revoked.
func (l *StoreRevocationList) IsRevoked(tokenID string) bool {
	_, err := l.backend.Get(context.Background(), storage.KindRevocation, tokenID)
	if err == nil {
		return true
	}
	return !errors.Is(err, storage.ErrNotFound)
}

var _ RevocationChecker = (*StoreRevocationList)(nil)
