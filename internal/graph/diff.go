package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// Change statuses.
const (
	ChangeAdded    = "added"
	ChangeModified = "modified"
	ChangeDeleted  = "deleted"
)

// FileChange is one path that differs between two states of a workspace.
type FileChange struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	// Before and After are blob IDs, which are BLAKE3 digests of the content:
	// equal IDs mean equal content. Empty on the side where the file is absent.
	Before     string `json:"before,omitempty"`
	After      string `json:"after,omitempty"`
	BeforeSize int    `json:"before_size"`
	AfterSize  int    `json:"after_size"`
}

// Manifest returns every file in an attempt's current workspace: its base
// world's files with the workspace's changes applied. Values are blob IDs.
func (s *Store) Manifest(ctx context.Context, attemptID string) (map[string]string, error) {
	attempt, err := loadAttempt(ctx, s.backend, attemptID)
	if err != nil {
		return nil, fmt.Errorf("load attempt %q: %w", attemptID, err)
	}
	manifest, err := s.baseManifest(ctx, attempt)
	if err != nil {
		return nil, err
	}
	overlay, err := s.Workspace(ctx, attemptID)
	if err != nil {
		return nil, err
	}
	for path, blob := range overlay {
		if blob == "" {
			delete(manifest, path)
		} else {
			manifest[path] = blob
		}
	}
	return manifest, nil
}

// baseManifest returns a private copy of an attempt's base world's files.
func (s *Store) baseManifest(ctx context.Context, attempt specv1.Attempt) (map[string]string, error) {
	out := map[string]string{}
	if attempt.BaseWorld == EmptyWorld() {
		return out, nil
	}
	m, err := loadManifest(ctx, s.backend, attempt.BaseWorld)
	if err != nil {
		return nil, err
	}
	for k, v := range m {
		out[k] = v
	}
	return out, nil
}

// Changes lists what differs in an attempt's workspace: from its base world, or,
// when against names another attempt, from that attempt's workspace (what this
// attempt would change if it replaced the other). Sorted by path.
func (s *Store) Changes(ctx context.Context, attemptID, against string) ([]FileChange, error) {
	attempt, err := loadAttempt(ctx, s.backend, attemptID)
	if err != nil {
		return nil, fmt.Errorf("load attempt %q: %w", attemptID, err)
	}
	after, err := s.Manifest(ctx, attemptID)
	if err != nil {
		return nil, err
	}
	var before map[string]string
	if against == "" {
		before, err = s.baseManifest(ctx, attempt)
	} else {
		before, err = s.Manifest(ctx, against)
	}
	if err != nil {
		return nil, err
	}

	var changes []FileChange
	for path, a := range after {
		switch b, ok := before[path]; {
		case !ok:
			changes = append(changes, FileChange{Path: path, Status: ChangeAdded, After: a})
		case b != a:
			changes = append(changes, FileChange{Path: path, Status: ChangeModified, Before: b, After: a})
		}
	}
	for path, b := range before {
		if _, ok := after[path]; !ok {
			changes = append(changes, FileChange{Path: path, Status: ChangeDeleted, Before: b})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	for i := range changes {
		for _, side := range []struct {
			blob string
			size *int
		}{{changes[i].Before, &changes[i].BeforeSize}, {changes[i].After, &changes[i].AfterSize}} {
			if side.blob == "" {
				continue
			}
			content, bErr := s.backend.GetBlob(ctx, storage.BlobID(side.blob))
			if bErr != nil {
				return nil, fmt.Errorf("graph: read blob for %q: %w", changes[i].Path, bErr)
			}
			*side.size = len(content)
		}
	}
	return changes, nil
}

// Blob returns the content of a stored blob.
func (s *Store) Blob(ctx context.Context, id string) ([]byte, error) {
	return s.backend.GetBlob(ctx, storage.BlobID(id))
}

// ---- evidence queries (evidence.query) ---------------------------------------

// EvidenceFilter selects evidence. Zero fields match everything.
type EvidenceFilter struct {
	Attempt     string
	Intent      string
	Kind        string
	Outcome     string
	Producer    string
	World       string // a prefix of the world hash
	Independent *bool
	// Standing is "counted", "stale" or "superseded"; empty matches all.
	Standing string
}

// EvidenceView is a piece of evidence as a query returns it.
type EvidenceView struct {
	EvidenceSummary
	Attempt  string `json:"attempt"`
	Intent   string `json:"intent"`
	Standing string `json:"standing"`
}

// QueryEvidence returns the evidence matching f, oldest first within each
// attempt, each with its current standing: counted (fresh and not superseded),
// stale (bound to a world the attempt has moved past) or superseded.
func (s *Store) QueryEvidence(ctx context.Context, f EvidenceFilter) ([]EvidenceView, error) {
	attempts, err := s.ListAttempts(ctx, f.Intent)
	if err != nil {
		return nil, err
	}
	out := []EvidenceView{}
	for _, a := range attempts {
		if f.Attempt != "" && a.ID != f.Attempt {
			continue
		}
		report, rErr := BuildAttemptReport(ctx, s, a)
		if rErr != nil {
			return nil, rErr
		}
		for _, e := range report.Evidence {
			standing := "counted"
			switch {
			case e.SupersededBy != "":
				standing = "superseded"
			case !e.Fresh:
				standing = "stale"
			}
			switch {
			case f.Kind != "" && e.Kind != f.Kind,
				f.Outcome != "" && e.Outcome != f.Outcome,
				f.Producer != "" && e.Producer != f.Producer,
				f.World != "" && !strings.HasPrefix(e.World, f.World),
				f.Independent != nil && e.Independent != *f.Independent,
				f.Standing != "" && standing != f.Standing:
				continue
			}
			out = append(out, EvidenceView{EvidenceSummary: e, Attempt: a.ID, Intent: a.Intent, Standing: standing})
		}
	}
	return out, nil
}
