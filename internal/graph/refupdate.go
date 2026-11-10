package graph

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// RefUpdateParams describes one observed ref update to record.
type RefUpdateParams struct {
	Repo      string
	Ref       string
	OldCommit string
	NewCommit string

	World     specv1.WorldHash
	BaseWorld *specv1.WorldHash

	PushedBy string
	Token    *specv1.CapabilityToken

	Intent          string
	ImplicitIntent  bool
	ChangedPaths    int
	ScopeViolations []specv1.ScopeViolation

	SecretScan          string
	SecretFindings      []specv1.SecretFinding
	SecretScanTruncated bool

	// SignedBy is the principal whose key signs the record: the server vouching
	// for what the push did.
	SignedBy string
}

// RecordRefUpdate appends a signed record of a ref update (FR-2.2). If an
// attempt already has exactly this world, the record links to it: the push
// delivered the tree that attempt produced. The intent must exist.
func (s *Store) RecordRefUpdate(ctx context.Context, p RefUpdateParams, key ed25519.PrivateKey) (specv1.RefUpdate, error) {
	rec := specv1.RefUpdate{
		Repo: p.Repo, Ref: p.Ref, OldCommit: p.OldCommit, NewCommit: p.NewCommit,
		World: p.World, BaseWorld: p.BaseWorld, PushedBy: p.PushedBy, Token: p.Token,
		Intent: p.Intent, ImplicitIntent: p.ImplicitIntent,
		ChangedPaths: p.ChangedPaths, ScopeViolations: p.ScopeViolations,
		SecretScan: p.SecretScan, SecretFindings: p.SecretFindings, SecretScanTruncated: p.SecretScanTruncated,
		At: time.Now().UTC(), SignedBy: p.SignedBy,
	}
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		if _, err := loadIntent(ctx, tx, p.Intent); err != nil {
			return err
		}
		attempt, err := attemptWithWorld(ctx, tx, p.World, p.Intent)
		if err != nil {
			return err
		}
		rec.Attempt = attempt

		id, err := specv1.NewContentID("ref_", rec)
		if err != nil {
			return fmt.Errorf("graph: generate ref update id: %w", err)
		}
		rec.ID = id
		signature, err := crypto.Sign(rec, key)
		if err != nil {
			return fmt.Errorf("graph: sign ref update: %w", err)
		}
		rec.Signature = signature
		if err = rec.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidParams, err)
		}
		encoded, err := specv1.Canonicalize(rec)
		if err != nil {
			return fmt.Errorf("graph: encode ref update: %w", err)
		}
		return putImmutable(ctx, tx, storage.KindRefUpdate, rec.ID, encoded)
	})
	if err != nil {
		return specv1.RefUpdate{}, err
	}
	return rec, nil
}

// attemptWithWorld returns the ID of the oldest attempt on intent whose current
// world is world, or "".
func attemptWithWorld(ctx context.Context, tx storage.Tx, world specv1.WorldHash, intent string) (string, error) {
	records, err := tx.List(ctx, storage.KindAttempt)
	if err != nil {
		return "", err
	}
	var best specv1.Attempt
	for id := range records {
		a, loadErr := loadAttempt(ctx, tx, id)
		if loadErr != nil {
			return "", loadErr
		}
		if a.Intent != intent || a.World != world || a.World == a.BaseWorld {
			continue
		}
		if best.ID == "" || a.CreatedAt.Before(best.CreatedAt) {
			best = a
		}
	}
	return best.ID, nil
}

// ListRefUpdates returns recorded ref updates, oldest first. A non-empty repo
// or ref restricts the result.
func (s *Store) ListRefUpdates(ctx context.Context, repo, ref string) ([]specv1.RefUpdate, error) {
	records, err := s.backend.List(ctx, storage.KindRefUpdate)
	if err != nil {
		return nil, fmt.Errorf("graph: list ref updates: %w", err)
	}
	var out []specv1.RefUpdate
	for id, data := range records {
		var r specv1.RefUpdate
		if err = json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("graph: decode ref update %q: %w", id, err)
		}
		if (repo == "" || r.Repo == repo) && (ref == "" || r.Ref == ref) {
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
