package graph

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// SpendLimit is one spend ceiling to charge against.
type SpendLimit struct {
	TokenID       string
	CeilingMicros int64
}

type spendRecord struct {
	TokenID     string `json:"token_id"`
	SpentMicros int64  `json:"spent_micros"`
}

// chargeSpend adds cost to the running total of every limit, refusing if any
// total would pass its ceiling. It runs inside the caller's transaction, so a
// refused charge leaves nothing behind.
func chargeSpend(ctx context.Context, tx storage.Tx, limits []SpendLimit, cost int64) error {
	if cost <= 0 {
		return nil
	}
	for _, l := range limits {
		var rec spendRecord
		data, err := tx.Get(ctx, storage.KindTokenSpend, l.TokenID)
		switch {
		case err == nil:
			if err = json.Unmarshal(data, &rec); err != nil {
				return fmt.Errorf("graph: decode spend for %s: %w", l.TokenID, err)
			}
		case errors.Is(err, storage.ErrNotFound):
			rec = spendRecord{TokenID: l.TokenID}
		default:
			return err
		}
		if rec.SpentMicros+cost > l.CeilingMicros {
			return fmt.Errorf("%w: token %s has spent %d of %d, and this commit adds %d", identity.ErrSpendCeiling, l.TokenID, rec.SpentMicros, l.CeilingMicros, cost)
		}
		rec.SpentMicros += cost
		encoded, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err = tx.Put(ctx, storage.KindTokenSpend, l.TokenID, encoded); err != nil {
			return fmt.Errorf("graph: record spend: %w", err)
		}
	}
	return nil
}

// Spent returns the cost charged so far against a token's ceiling.
func (s *Store) Spent(ctx context.Context, tokenID string) (int64, error) {
	data, err := s.backend.Get(ctx, storage.KindTokenSpend, tokenID)
	if errors.Is(err, storage.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var rec spendRecord
	if err = json.Unmarshal(data, &rec); err != nil {
		return 0, fmt.Errorf("graph: decode spend for %s: %w", tokenID, err)
	}
	return rec.SpentMicros, nil
}

// AuthorityParams describes one write to record.
type AuthorityParams struct {
	Op        string
	Principal string
	// Token is the capability token the write was made under, with its whole
	// delegation chain.
	Token   specv1.CapabilityToken
	Object  string // ID of the object created or changed
	Attempt string // the attempt it belongs to, if any
	Intent  string // the intent it belongs to, if any
	Path    string // the path written, if any
}

// RecordAuthority appends a signed record of which capability chain authorised
// a write (FR-1.6). Records are never altered.
func (s *Store) RecordAuthority(ctx context.Context, p AuthorityParams, key ed25519.PrivateKey) (specv1.AuthorityRecord, error) {
	rec := specv1.AuthorityRecord{
		Op: p.Op, Principal: p.Principal, Token: p.Token,
		Object: p.Object, Attempt: p.Attempt, Intent: p.Intent, Path: p.Path,
		At: time.Now().UTC(),
	}
	id, err := specv1.NewContentID("aut_", rec)
	if err != nil {
		return specv1.AuthorityRecord{}, fmt.Errorf("graph: generate authority id: %w", err)
	}
	rec.ID = id
	signature, err := crypto.Sign(rec, key)
	if err != nil {
		return specv1.AuthorityRecord{}, fmt.Errorf("graph: sign authority record: %w", err)
	}
	rec.Signature = signature
	if err = rec.Validate(); err != nil {
		return specv1.AuthorityRecord{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	encoded, err := specv1.Canonicalize(rec)
	if err != nil {
		return specv1.AuthorityRecord{}, fmt.Errorf("graph: encode authority record: %w", err)
	}
	err = s.backend.Transaction(ctx, func(tx storage.Tx) error {
		return putImmutable(ctx, tx, storage.KindAuthority, rec.ID, encoded)
	})
	if err != nil {
		return specv1.AuthorityRecord{}, err
	}
	return rec, nil
}

// ListAuthority returns the records that concern ref, oldest first: those whose
// object, attempt or intent is ref. An empty ref returns every record.
func (s *Store) ListAuthority(ctx context.Context, ref string) ([]specv1.AuthorityRecord, error) {
	records, err := s.backend.List(ctx, storage.KindAuthority)
	if err != nil {
		return nil, fmt.Errorf("graph: list authority records: %w", err)
	}
	var out []specv1.AuthorityRecord
	for id, data := range records {
		var r specv1.AuthorityRecord
		if err = json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("graph: decode authority record %q: %w", id, err)
		}
		if ref == "" || r.Object == ref || r.Attempt == ref || r.Intent == ref {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
