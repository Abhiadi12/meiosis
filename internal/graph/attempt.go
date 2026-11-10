package graph

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zeebo/blake3"

	"github.com/mindfire-test/meiosis/internal/scope"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
	"github.com/mindfire-test/meiosis/pkg/worlds"
)

var (
	// ErrScopeViolation is matched (errors.Is) by the *ScopeError returned when
	// a write falls outside an intent's scope in enforce mode (FR-3.4).
	ErrScopeViolation = errors.New("graph: path is outside the intent's scope")
	// ErrNotAuthor is returned when a principal other than the attempt's
	// author tries to modify it.
	ErrNotAuthor = errors.New("graph: only the attempt's author may modify it")
	// ErrIntentClosed is returned when an attempt is opened on an intent that
	// is no longer open.
	ErrIntentClosed = errors.New("graph: intent is not open for attempts")
	// ErrUnknownWorld is returned when an attempt's base world has no stored
	// manifest.
	ErrUnknownWorld = errors.New("graph: unknown base world")
)

// ScopeError is the legible rejection for an out-of-scope write.
type ScopeError struct {
	Intent string
	Path   string
	Reason string
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("path %q is outside the scope of intent %s: %s (scope mode: enforce)", e.Path, e.Intent, e.Reason)
}

// Is makes errors.Is(err, ErrScopeViolation) true for a *ScopeError.
func (e *ScopeError) Is(target error) bool { return target == ErrScopeViolation }

// EmptyWorld is the hash of the empty tree: the base world of an attempt that
// starts from nothing. Until git serving supplies real base worlds (M1
// Phase 6), an attempt's workspace is an overlay on this base.
func EmptyWorld() specv1.WorldHash {
	tree, err := worlds.NewMemoryTree(nil)
	if err != nil {
		panic(err) // an empty tree is always valid
	}
	world, err := worlds.New(context.Background(), tree)
	if err != nil {
		panic(err)
	}
	return world.Hash()
}

// OpenAttemptParams describes the attempt being opened.
type OpenAttemptParams struct {
	Intent    string
	Author    string
	BaseWorld specv1.WorldHash // zero means EmptyWorld()
}

// OpenAttempt creates a signed, open attempt on an intent. Its workspace
// starts as its base world, with nothing written yet.
func (s *Store) OpenAttempt(ctx context.Context, p OpenAttemptParams, signerKey ed25519.PrivateKey) (specv1.Attempt, error) {
	base := p.BaseWorld
	if base == (specv1.WorldHash{}) {
		base = EmptyWorld()
	}
	var attempt specv1.Attempt
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		view, err := loadIntentView(ctx, tx, p.Intent)
		if err != nil {
			return err
		}
		if !view.Open() {
			if view.SupersededBy != "" {
				return fmt.Errorf("%w: %s is superseded by %s", ErrIntentClosed, view.ID, view.SupersededBy)
			}
			return fmt.Errorf("%w: %s is %s", ErrIntentClosed, view.ID, view.CurrentStatus)
		}
		if base != EmptyWorld() {
			if _, mErr := loadManifest(ctx, tx, base); mErr != nil {
				return mErr
			}
		}

		attempt = specv1.Attempt{
			Intent:    p.Intent,
			Author:    p.Author,
			World:     base,
			BaseWorld: base,
			Status:    specv1.AttemptStatusOpen,
			CreatedAt: time.Now().UTC(),
		}
		id, err := specv1.NewContentID("att_", attempt)
		if err != nil {
			return fmt.Errorf("graph: generate attempt id: %w", err)
		}
		attempt.ID = id
		if err = putAttemptCreation(ctx, tx, &attempt, signerKey); err != nil {
			return err
		}
		if _, err = appendOp(ctx, tx, attempt.ID, newOp{kind: specv1.OperationOpen, by: p.Author}, signerKey); err != nil {
			return err
		}
		return markAttempting(ctx, tx, view, p.Author, signerKey)
	})
	if err != nil {
		return specv1.Attempt{}, err
	}
	return attempt, nil
}

// WriteParams describes one file operation inside an attempt.
type WriteParams struct {
	Attempt string
	Author  string // the principal performing the write
	Path    string
	Content []byte
	Delete  bool
}

// WriteResult is the outcome of an accepted write.
type WriteResult struct {
	Attempt specv1.Attempt
	// Violation is set when the path was outside scope but the intent's mode
	// is "warn": the write was accepted and recorded on the attempt.
	Violation *specv1.ScopeViolation
}

// WriteFile applies one write (or deletion) to an attempt's workspace,
// enforcing the intent's scope at write time (FR-3.4). In enforce mode an
// out-of-scope path is rejected with a *ScopeError and nothing is stored; in
// warn mode it is stored and recorded in the attempt's ScopeViolations.
func (s *Store) WriteFile(ctx context.Context, p WriteParams, signerKey ed25519.PrivateKey) (WriteResult, error) {
	var result WriteResult
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		attempt, err := loadActiveAttempt(ctx, tx, p.Attempt)
		if err != nil {
			return err
		}
		if attempt.Author != p.Author {
			return fmt.Errorf("%w: attempt %s belongs to %s", ErrNotAuthor, attempt.ID, attempt.Author)
		}
		intent, err := loadIntent(ctx, tx, attempt.Intent)
		if err != nil {
			return err
		}

		violation, err := checkScope(intent, p.Path)
		if err != nil {
			return err
		}
		changed := false
		if violation != nil {
			attempt, changed = recordViolation(attempt, *violation)
			result.Violation = violation
		}

		if p.Delete {
			if _, err = appendOp(ctx, tx, attempt.ID, newOp{kind: specv1.OperationDelete, path: p.Path, by: p.Author}, signerKey); err != nil {
				return err
			}
		} else {
			blob, putErr := tx.PutBlob(ctx, p.Content)
			if putErr != nil {
				return fmt.Errorf("graph: store file content: %w", putErr)
			}
			if _, err = appendOp(ctx, tx, attempt.ID, newOp{kind: specv1.OperationWrite, path: p.Path, blob: string(blob), by: p.Author}, signerKey); err != nil {
				return err
			}
		}
		if changed {
			if err := putAttemptState(ctx, tx, &attempt, signerKey); err != nil {
				return err
			}
		}
		result.Attempt = attempt
		return nil
	})
	if err != nil {
		return WriteResult{}, err
	}
	return result, nil
}

// CommitParams carries the provenance an agent reports when committing.
type CommitParams struct {
	Attempt string
	Author  string

	Model      string
	ModelVer   string
	Tools      []string
	Prompt     string // hashed, never stored (NFR-4.2)
	PromptHash string // alternative to Prompt: a ready 64-hex BLAKE3 digest
	Seed       *int64
	Params     map[string]string
	TokensIn   int64
	TokensOut  int64
	CostMicros int64

	// SpendLimits are the spend ceilings of the capability chain the commit is
	// made under (FR-1.4). The reported CostMicros is charged against every one
	// of them in the commit's own transaction, and the commit is refused if it
	// would push any past its ceiling.
	SpendLimits []SpendLimit
}

// CommitResult is the outcome of a commit.
type CommitResult struct {
	Attempt     specv1.Attempt
	Attestation specv1.Attestation
	Files       []string
	Changed     []string
}

// unreported marks provenance fields the agent did not supply. They are
// recorded honestly as "unknown" rather than invented.
const unreported = "unknown"

// CommitAttempt snapshots the attempt's workspace into a world, re-checks the
// diff against the intent's scope, binds the attempt to the new world hash and
// records a signed attestation, all in one transaction. It may be called again
// after further writes; each commit supersedes the previous world and
// attestation.
func (s *Store) CommitAttempt(ctx context.Context, p CommitParams, signerKey ed25519.PrivateKey) (CommitResult, error) {
	var result CommitResult
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		attempt, err := loadActiveAttempt(ctx, tx, p.Attempt)
		if err != nil {
			return err
		}
		if attempt.Author != p.Author {
			return fmt.Errorf("%w: attempt %s belongs to %s", ErrNotAuthor, attempt.ID, attempt.Author)
		}
		intent, err := loadIntent(ctx, tx, attempt.Intent)
		if err != nil {
			return err
		}

		baseManifest := map[string]string{}
		if attempt.BaseWorld != EmptyWorld() {
			if baseManifest, err = loadManifest(ctx, tx, attempt.BaseWorld); err != nil {
				return err
			}
		}
		head, err := loadHead(ctx, tx, attempt.ID)
		if err != nil {
			return err
		}
		overlay, err := overlayAt(ctx, tx, head)
		if err != nil {
			return err
		}
		manifest := make(map[string]string, len(baseManifest)+len(overlay))
		for path, blob := range baseManifest {
			manifest[path] = blob
		}
		for path, blob := range overlay {
			if blob == "" {
				delete(manifest, path)
			} else {
				manifest[path] = blob
			}
		}

		files := make(map[string][]byte, len(manifest))
		for path, blob := range manifest {
			content, gErr := tx.GetBlob(ctx, storage.BlobID(blob))
			if gErr != nil {
				return fmt.Errorf("graph: read blob for %q: %w", path, gErr)
			}
			files[path] = content
		}
		tree, err := worlds.NewMemoryTree(files)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidParams, err)
		}
		world, err := worlds.New(ctx, tree)
		if err != nil {
			return err
		}

		// The spec requires the base→world diff to be checked against scope.
		changed := changedPaths(baseManifest, manifest)
		for _, path := range changed {
			violation, vErr := checkScope(intent, path)
			if vErr != nil {
				return vErr
			}
			if violation != nil {
				attempt, _ = recordViolation(attempt, *violation)
			}
		}

		manifestBytes, err := specv1.Canonicalize(manifest)
		if err != nil {
			return fmt.Errorf("graph: encode world manifest: %w", err)
		}
		if err = putImmutable(ctx, tx, storage.KindWorld, world.Hash().String(), manifestBytes); err != nil {
			return fmt.Errorf("graph: persist world: %w", err)
		}

		prevWorld, newWorld := attempt.World, world.Hash()
		attempt.World = newWorld
		if err = putAttemptState(ctx, tx, &attempt, signerKey); err != nil {
			return err
		}

		// One attestation per committed world, immutable once recorded. A
		// recommit that lands on a world already attested keeps the original
		// provenance rather than rewriting it.
		attestation, err := loadAttestation(ctx, tx, attempt.ID, attempt.World)
		if errors.Is(err, storage.ErrNotFound) {
			if attestation, err = buildAttestation(attempt, p, signerKey); err != nil {
				return err
			}
			encoded, encErr := specv1.Canonicalize(attestation)
			if encErr != nil {
				return fmt.Errorf("graph: encode attestation: %w", encErr)
			}
			// The cost is charged only when a new attestation is recorded: a
			// recommit onto an already-attested world keeps its provenance and
			// so must not be billed twice.
			if err = chargeSpend(ctx, tx, p.SpendLimits, attestation.CostMicros); err != nil {
				return err
			}
			if err = putImmutable(ctx, tx, storage.KindAttestation, attestationKey(attempt.ID, attempt.World), encoded); err != nil {
				return fmt.Errorf("graph: persist attestation: %w", err)
			}
		} else if err != nil {
			return err
		}

		if _, err = appendOp(ctx, tx, attempt.ID, newOp{kind: specv1.OperationCommit, world: &newWorld, prevWorld: &prevWorld, by: p.Author}, signerKey); err != nil {
			return err
		}

		paths := make([]string, 0, len(files))
		for path := range files {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		result = CommitResult{Attempt: attempt, Attestation: attestation, Files: paths, Changed: changed}
		return nil
	})
	if err != nil {
		return CommitResult{}, err
	}
	return result, nil
}

func buildAttestation(attempt specv1.Attempt, p CommitParams, key ed25519.PrivateKey) (specv1.Attestation, error) {
	promptHash := p.PromptHash
	switch {
	case promptHash != "":
	case p.Prompt != "":
		sum := blake3.Sum256([]byte(p.Prompt))
		promptHash = specv1.DigestHex(sum)
	default:
		sum := blake3.Sum256(nil) // no prompt reported
		promptHash = specv1.DigestHex(sum)
	}
	model, modelVer := p.Model, p.ModelVer
	if strings.TrimSpace(model) == "" {
		model = unreported
	}
	if strings.TrimSpace(modelVer) == "" {
		modelVer = unreported
	}
	tools := p.Tools
	if len(tools) == 0 {
		tools = []string{"attempt_write", "attempt_commit"}
	}
	attestation := specv1.Attestation{
		Attempt:    attempt.ID,
		Agent:      attempt.Author,
		Model:      model,
		ModelVer:   modelVer,
		Tools:      tools,
		PromptHash: promptHash,
		Seed:       p.Seed,
		Params:     p.Params,
		TokensIn:   p.TokensIn,
		TokensOut:  p.TokensOut,
		CostMicros: p.CostMicros,
	}
	signature, err := crypto.Sign(attestation, key)
	if err != nil {
		return specv1.Attestation{}, fmt.Errorf("graph: sign attestation: %w", err)
	}
	attestation.Signature = signature
	if err := attestation.Validate(); err != nil {
		return specv1.Attestation{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return attestation, nil
}

// checkScope evaluates path against the intent's scope. It returns nil when
// the path is allowed, a violation when it is not and the mode is "warn", and
// a *ScopeError when it is not and the mode is "enforce".
func checkScope(intent specv1.Intent, path string) (*specv1.ScopeViolation, error) {
	decision, err := scope.New(intent.Scope).Evaluate(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	if decision.Allowed {
		return nil, nil
	}
	if intent.Scope.Mode == specv1.ScopeModeWarn {
		return &specv1.ScopeViolation{Path: path, Reason: decision.Reason}, nil
	}
	return nil, &ScopeError{Intent: intent.ID, Path: path, Reason: decision.Reason}
}

// recordViolation adds v to the attempt unless its path is already recorded.
// It reports whether the attempt changed.
func recordViolation(a specv1.Attempt, v specv1.ScopeViolation) (specv1.Attempt, bool) {
	for _, existing := range a.ScopeViolations {
		if existing.Path == v.Path {
			return a, false
		}
	}
	a.ScopeViolations = append(append([]specv1.ScopeViolation(nil), a.ScopeViolations...), v)
	return a, true
}

// changedPaths lists, sorted, every path whose content differs between two
// manifests (blob IDs are content hashes, so equal IDs mean equal content).
func changedPaths(before, after map[string]string) []string {
	var changed []string
	for path, blob := range after {
		if before[path] != blob {
			changed = append(changed, path)
		}
	}
	for path := range before {
		if _, ok := after[path]; !ok {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}

func loadIntent(ctx context.Context, tx storage.Tx, id string) (specv1.Intent, error) {
	data, err := tx.Get(ctx, storage.KindIntent, id)
	if err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: load intent %q: %w", id, err)
	}
	var intent specv1.Intent
	if err := json.Unmarshal(data, &intent); err != nil {
		return specv1.Intent{}, fmt.Errorf("graph: decode intent %q: %w", id, err)
	}
	return intent, nil
}

func loadManifest(ctx context.Context, tx getter, hash specv1.WorldHash) (map[string]string, error) {
	data, err := tx.Get(ctx, storage.KindWorld, hash.String())
	if errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownWorld, hash)
	}
	if err != nil {
		return nil, err
	}
	manifest := map[string]string{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("graph: decode world manifest %s: %w", hash, err)
	}
	return manifest, nil
}

// ---- reads ----------------------------------------------------------------

// ListAttempts returns every attempt, oldest first. A non-empty intentID
// restricts the result to that intent.
func (s *Store) ListAttempts(ctx context.Context, intentID string) ([]specv1.Attempt, error) {
	records, err := s.backend.List(ctx, storage.KindAttempt)
	if err != nil {
		return nil, fmt.Errorf("graph: list attempts: %w", err)
	}
	states, err := s.backend.List(ctx, storage.KindAttemptState)
	if err != nil {
		return nil, fmt.Errorf("graph: list attempt states: %w", err)
	}
	attempts := make([]specv1.Attempt, 0, len(records))
	for id, data := range records {
		if state, ok := states[id]; ok {
			data = state // the current view supersedes the creation record
		}
		var a specv1.Attempt
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("graph: decode attempt %q: %w", id, err)
		}
		if intentID == "" || a.Intent == intentID {
			attempts = append(attempts, a)
		}
	}
	sort.Slice(attempts, func(i, j int) bool {
		if !attempts[i].CreatedAt.Equal(attempts[j].CreatedAt) {
			return attempts[i].CreatedAt.Before(attempts[j].CreatedAt)
		}
		return attempts[i].ID < attempts[j].ID
	})
	return attempts, nil
}

// attestationKey addresses the attestation for one committed world of an
// attempt.
func attestationKey(attemptID string, world specv1.WorldHash) string {
	return attemptID + ":" + world.String()
}

func loadAttestation(ctx context.Context, g getter, attemptID string, world specv1.WorldHash) (specv1.Attestation, error) {
	data, err := g.Get(ctx, storage.KindAttestation, attestationKey(attemptID, world))
	if err != nil {
		return specv1.Attestation{}, err
	}
	var a specv1.Attestation
	if err := json.Unmarshal(data, &a); err != nil {
		return specv1.Attestation{}, fmt.Errorf("graph: decode attestation for %q: %w", attemptID, err)
	}
	return a, nil
}

// GetAttestation returns the attestation recorded when attempt reached world,
// or storage.ErrNotFound if that world was never committed.
func (s *Store) GetAttestation(ctx context.Context, attemptID string, world specv1.WorldHash) (specv1.Attestation, error) {
	return loadAttestation(ctx, s.backend, attemptID, world)
}

// ListEvidence returns the evidence recorded against an attempt, oldest first.
func (s *Store) ListEvidence(ctx context.Context, attemptID string) ([]specv1.Evidence, error) {
	records, err := s.backend.List(ctx, storage.KindEvidence)
	if err != nil {
		return nil, fmt.Errorf("graph: list evidence: %w", err)
	}
	var out []specv1.Evidence
	for id, data := range records {
		var e specv1.Evidence
		if err := json.Unmarshal(data, &e); err != nil {
			return nil, fmt.Errorf("graph: decode evidence %q: %w", id, err)
		}
		if attemptID == "" || e.Attempt == attemptID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// WorkspaceFiles returns the paths currently written (or deleted) in an
// attempt's workspace, each sorted.
func (s *Store) WorkspaceFiles(ctx context.Context, attemptID string) (written, deleted []string, err error) {
	overlay, err := s.Workspace(ctx, attemptID)
	if err != nil {
		return nil, nil, err
	}
	for _, path := range sortedPaths(overlay) {
		if overlay[path] == "" {
			deleted = append(deleted, path)
		} else {
			written = append(written, path)
		}
	}
	return written, deleted, nil
}

// Workspace returns an attempt's current overlay: path to blob ID, with "" for a
// deleted file. Paths not present are as in the attempt's base world.
func (s *Store) Workspace(ctx context.Context, attemptID string) (map[string]string, error) {
	head, err := loadHead(ctx, s.backend, attemptID)
	if err != nil {
		return nil, err
	}
	return overlayAt(ctx, s.backend, head)
}
