package graph

import (
	"context"
	"errors"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

// EvidenceSummary is one evidence record as shown in an attempt report.
type EvidenceSummary struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Outcome     string `json:"outcome"`
	Producer    string `json:"producer"`
	Independent bool   `json:"independent"`
	World       string `json:"world"`
	// Fresh is true when the evidence was produced against the attempt's
	// current world. Footprint-based invalidation arrives in M2.
	Fresh bool `json:"fresh"`
	// SupersededBy is the record that corrected this one, if any (FR-4.12).
	SupersededBy string `json:"superseded_by,omitempty"`
	// Counted is true only for evidence that may satisfy a policy: fresh and
	// not superseded. Stale and superseded evidence is kept but never counted.
	Counted bool `json:"counted"`
}

// AttemptReport is the human- and agent-readable state of an attempt: what it
// is, what its workspace holds, who produced it and what has been verified.
type AttemptReport struct {
	Attempt     specv1.Attempt      `json:"attempt"`
	Committed   bool                `json:"committed"`
	Attestation *specv1.Attestation `json:"attestation,omitempty"`
	Written     []string            `json:"workspace_files"`
	Deleted     []string            `json:"workspace_deletions"`
	Evidence    []EvidenceSummary   `json:"evidence"`
}

// BuildAttemptReport assembles the report for attempt.
func BuildAttemptReport(ctx context.Context, s *Store, attempt specv1.Attempt) (AttemptReport, error) {
	report := AttemptReport{
		Attempt:   attempt,
		Committed: attempt.World != attempt.BaseWorld,
		Written:   []string{},
		Deleted:   []string{},
		Evidence:  []EvidenceSummary{},
	}

	attestation, err := s.GetAttestation(ctx, attempt.ID, attempt.World)
	switch {
	case err == nil:
		report.Attestation = &attestation
		report.Committed = true
	case !errors.Is(err, storage.ErrNotFound):
		return AttemptReport{}, err
	}

	written, deleted, err := s.WorkspaceFiles(ctx, attempt.ID)
	if err != nil {
		return AttemptReport{}, err
	}
	if written != nil {
		report.Written = written
	}
	if deleted != nil {
		report.Deleted = deleted
	}

	evidence, err := s.ListEvidence(ctx, attempt.ID)
	if err != nil {
		return AttemptReport{}, err
	}
	superseded := SupersededBy(evidence)
	for _, e := range evidence {
		fresh := e.World == attempt.World
		report.Evidence = append(report.Evidence, EvidenceSummary{
			ID: e.ID, Kind: string(e.Kind), Outcome: string(e.Outcome), Producer: e.Producer,
			Independent: e.Independent, World: e.World.String(), Fresh: fresh,
			SupersededBy: superseded[e.ID], Counted: fresh && superseded[e.ID] == "",
		})
	}
	return report, nil
}
