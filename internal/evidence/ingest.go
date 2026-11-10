package evidence

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/mindfire-test/meiosis/internal/graph"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// IngestParams describes one report to turn into evidence.
type IngestParams struct {
	Attempt  string
	Producer string
	// World is the world hash the report was produced against. It is required:
	// evidence not bound to a world is rejected (FR-4.1).
	World specv1.WorldHash
	// Format of the report; empty means detect it from the content.
	Format     Format
	Options    Options
	Footprint  []string
	Supersedes string
}

// Ingest parses a report and records it as signed evidence bound to p.World.
// The attempt check, independence computation and write happen in one
// transaction inside the graph store; the outcome comes from the report, never
// from the caller.
func Ingest(ctx context.Context, store *graph.Store, p IngestParams, key ed25519.PrivateKey, report []byte) (specv1.Evidence, Report, error) {
	if store == nil {
		return specv1.Evidence{}, Report{}, fmt.Errorf("evidence graph store must not be nil")
	}
	format := p.Format
	if format == "" {
		detected, err := Detect(report)
		if err != nil {
			return specv1.Evidence{}, Report{}, err
		}
		format = detected
	}
	parsed, err := Parse(format, report, p.Options)
	if err != nil {
		return specv1.Evidence{}, Report{}, err
	}
	evidence, err := store.SubmitEvidence(ctx, graph.SubmitEvidenceParams{
		Attempt:    p.Attempt,
		Producer:   p.Producer,
		World:      p.World,
		Kind:       parsed.Kind,
		Outcome:    parsed.Outcome,
		Payload:    parsed.Payload,
		Footprint:  p.Footprint,
		Supersedes: p.Supersedes,
	}, key)
	if err != nil {
		return specv1.Evidence{}, Report{}, fmt.Errorf("persist evidence: %w", err)
	}
	return evidence, parsed, nil
}

// IngestGoTestJSON parses go test -json output, signs the resulting Evidence,
// and stores it with the active attempt as one atomic operation.
func IngestGoTestJSON(ctx context.Context, store *graph.Store, attemptID, producer string, world specv1.WorldHash, privateKey ed25519.PrivateKey, input io.Reader) (specv1.Evidence, error) {
	data, err := ReadReport(input)
	if err != nil {
		return specv1.Evidence{}, err
	}
	evidence, _, err := Ingest(ctx, store, IngestParams{Attempt: attemptID, Producer: producer, World: world, Format: FormatGoTest}, privateKey, data)
	return evidence, err
}
