package graph

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

var (
	// ErrNotUndoable is returned for an operation that cannot be reverted.
	ErrNotUndoable = errors.New("graph: operation cannot be undone")
	// ErrUnknownOperation is returned when a named operation does not exist in
	// the attempt's log.
	ErrUnknownOperation = errors.New("graph: unknown operation")
)

// maxLogWalk bounds how far back any walk of an operation log goes. Content-
// derived IDs make a cycle impossible, so this only limits a corrupt store.
const maxLogWalk = 1 << 20

// workspaceRecord is the one mutable fact about a workspace: which operation
// is its latest. Everything else is derived from the immutable log.
type workspaceRecord struct {
	Head string `json:"head"`
}

func loadHead(ctx context.Context, g getter, attemptID string) (string, error) {
	data, err := g.Get(ctx, storage.KindWorkspace, attemptID)
	if errors.Is(err, storage.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var rec workspaceRecord
	if err = json.Unmarshal(data, &rec); err != nil {
		return "", fmt.Errorf("graph: decode workspace %q: %w", attemptID, err)
	}
	return rec.Head, nil
}

func saveHead(ctx context.Context, tx storage.Tx, attemptID, head string) error {
	data, err := json.Marshal(workspaceRecord{Head: head})
	if err != nil {
		return err
	}
	return tx.Put(ctx, storage.KindWorkspace, attemptID, data)
}

func loadOp(ctx context.Context, g getter, id string) (specv1.Operation, error) {
	data, err := g.Get(ctx, storage.KindOperation, id)
	if err != nil {
		return specv1.Operation{}, fmt.Errorf("graph: load operation %q: %w", id, err)
	}
	var op specv1.Operation
	if err = json.Unmarshal(data, &op); err != nil {
		return specv1.Operation{}, fmt.Errorf("graph: decode operation %q: %w", id, err)
	}
	return op, nil
}

// apply updates overlay with the effect of op on the files.
func apply(overlay map[string]string, op specv1.Operation) {
	switch op.Kind {
	case specv1.OperationWrite:
		overlay[op.Path] = op.Blob
	case specv1.OperationDelete:
		overlay[op.Path] = ""
	case specv1.OperationRevert:
		switch {
		case op.Path == "":
			// A revert of a commit changes the world, not the files.
		case op.Unset:
			delete(overlay, op.Path)
		default:
			overlay[op.Path] = op.Blob
		}
	}
}

// overlayAt returns the workspace's files as of operation head: a map from path
// to blob ID, "" meaning deleted. It reads back to the nearest snapshot, so at
// most specv1.SnapshotInterval operations, however long the history.
func overlayAt(ctx context.Context, g getter, head string) (map[string]string, error) {
	var pending []specv1.Operation
	overlay := map[string]string{}
	for id, steps := head, 0; id != ""; steps++ {
		if steps > maxLogWalk {
			return nil, errors.New("graph: operation log is implausibly long or cyclic")
		}
		op, err := loadOp(ctx, g, id)
		if err != nil {
			return nil, err
		}
		if op.Snapshot != nil {
			for k, v := range op.Snapshot {
				overlay[k] = v
			}
			break
		}
		pending = append(pending, op)
		id = op.Parent
	}
	for i := len(pending) - 1; i >= 0; i-- {
		apply(overlay, pending[i])
	}
	return overlay, nil
}

// newOp describes an operation to append.
type newOp struct {
	kind       specv1.OperationKind
	parent     string // overrides the workspace's head, for the first operation of a fork
	path, blob string
	unset      bool
	reverts    string
	forkedFrom string
	world      *specv1.WorldHash
	prevWorld  *specv1.WorldHash
	by         string
}

// appendOp signs and stores a new operation at the head of attemptID's log and
// moves the head to it, in the caller's transaction. Every SnapshotInterval
// operations it records the full overlay so reads stay short.
func appendOp(ctx context.Context, tx storage.Tx, attemptID string, n newOp, key ed25519.PrivateKey) (specv1.Operation, error) {
	parentID := n.parent
	if parentID == "" {
		head, err := loadHead(ctx, tx, attemptID)
		if err != nil {
			return specv1.Operation{}, err
		}
		parentID = head
	}
	op := specv1.Operation{
		Attempt: attemptID, Kind: n.kind, Parent: parentID, Path: n.path, Blob: n.blob, Unset: n.unset,
		Reverts: n.reverts, ForkedFrom: n.forkedFrom, World: n.world, PrevWorld: n.prevWorld,
		By: n.by, At: time.Now().UTC(),
	}
	if parentID != "" {
		parent, err := loadOp(ctx, tx, parentID)
		if err != nil {
			return specv1.Operation{}, err
		}
		op.Seq = parent.Seq + 1
	}
	if op.Seq > 0 && op.Seq%specv1.SnapshotInterval == 0 {
		overlay, err := overlayAt(ctx, tx, parentID)
		if err != nil {
			return specv1.Operation{}, err
		}
		apply(overlay, op)
		op.Snapshot = overlay
	}

	id, err := specv1.NewContentID("op_", op)
	if err != nil {
		return specv1.Operation{}, fmt.Errorf("graph: generate operation id: %w", err)
	}
	op.ID = id
	signature, err := crypto.Sign(op, key)
	if err != nil {
		return specv1.Operation{}, fmt.Errorf("graph: sign operation: %w", err)
	}
	op.Signature = signature
	if err = op.Validate(); err != nil {
		return specv1.Operation{}, fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	encoded, err := specv1.Canonicalize(op)
	if err != nil {
		return specv1.Operation{}, fmt.Errorf("graph: encode operation: %w", err)
	}
	if err = putImmutable(ctx, tx, storage.KindOperation, op.ID, encoded); err != nil {
		return specv1.Operation{}, fmt.Errorf("graph: persist operation: %w", err)
	}
	if err = saveHead(ctx, tx, attemptID, op.ID); err != nil {
		return specv1.Operation{}, err
	}
	return op, nil
}

// ForkParams describes forking an attempt's workspace.
type ForkParams struct {
	Source string // the attempt to fork
	Author string // who the new attempt belongs to
}

// ForkAttempt creates a new attempt on the same intent whose workspace starts
// as a copy of Source's current state (FR-2.3). Nothing is copied: the new
// workspace's log begins with one operation whose parent is the source's latest,
// so the cost is the same for an empty workspace and for one holding a hundred
// thousand files. Afterwards the two evolve independently. The fork shares the
// source's base world; it has no world of its own until it commits.
func (s *Store) ForkAttempt(ctx context.Context, p ForkParams, key ed25519.PrivateKey) (specv1.Attempt, error) {
	var forked specv1.Attempt
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		source, err := loadAttempt(ctx, tx, p.Source)
		if err != nil {
			return fmt.Errorf("load attempt %q: %w", p.Source, err)
		}
		view, err := loadIntentView(ctx, tx, source.Intent)
		if err != nil {
			return err
		}
		if !view.Open() {
			return fmt.Errorf("%w: %s is %s", ErrIntentClosed, view.ID, view.CurrentStatus)
		}
		head, err := loadHead(ctx, tx, source.ID)
		if err != nil {
			return err
		}

		forked = specv1.Attempt{
			Intent: source.Intent, Author: p.Author, World: source.BaseWorld, BaseWorld: source.BaseWorld,
			ForkedFrom: source.ID, Status: specv1.AttemptStatusOpen, CreatedAt: time.Now().UTC(),
		}
		id, err := specv1.NewContentID("att_", forked)
		if err != nil {
			return fmt.Errorf("graph: generate attempt id: %w", err)
		}
		forked.ID = id
		if err = putAttemptCreation(ctx, tx, &forked, key); err != nil {
			return err
		}
		if head == "" {
			// The source never had a log (it predates it): the fork starts empty.
			_, err = appendOp(ctx, tx, forked.ID, newOp{kind: specv1.OperationOpen, by: p.Author}, key)
			return err
		}
		_, err = appendOp(ctx, tx, forked.ID, newOp{kind: specv1.OperationFork, parent: head, forkedFrom: source.ID, by: p.Author}, key)
		return err
	})
	if err != nil {
		return specv1.Attempt{}, err
	}
	return forked, nil
}

// ListOperations returns an attempt's operation log, newest first, up to the
// point where its lineage begins or crosses into the attempt it was forked from.
func (s *Store) ListOperations(ctx context.Context, attemptID string) ([]specv1.Operation, error) {
	head, err := loadHead(ctx, s.backend, attemptID)
	if err != nil {
		return nil, err
	}
	var ops []specv1.Operation
	for id := head; id != ""; {
		if len(ops) > maxLogWalk {
			return nil, errors.New("graph: operation log is implausibly long or cyclic")
		}
		op, loadErr := loadOp(ctx, s.backend, id)
		if loadErr != nil {
			return nil, loadErr
		}
		if op.Attempt != attemptID {
			break // the source's history: not part of this workspace's own log
		}
		ops = append(ops, op)
		id = op.Parent
	}
	return ops, nil
}

// RevertParams describes undoing an operation.
type RevertParams struct {
	Attempt string
	Author  string
	// Operation is the operation to undo; empty means the latest one.
	Operation string
}

// RevertOperation undoes one operation by appending a new one, never by erasing
// history (FR-2.5, FR-2.6). Undoing a write, a delete or an earlier revert puts
// that path back as it was before that operation. Undoing a commit restores the
// exact world hash the attempt had before it, so evidence that was bound to that
// world is current again, with nothing re-run or rewritten. Undoing a revert is
// a redo.
//
// Only the latest commit can be undone, and only while its world is still the
// attempt's: rolling back a commit that later work has superseded would restore
// a world the attempt has already moved past.
func (s *Store) RevertOperation(ctx context.Context, p RevertParams, key ed25519.PrivateKey) (specv1.Operation, error) {
	var result specv1.Operation
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		attempt, err := loadActiveAttempt(ctx, tx, p.Attempt)
		if err != nil {
			return err
		}
		if attempt.Author != p.Author {
			return fmt.Errorf("%w: attempt %s belongs to %s", ErrNotAuthor, attempt.ID, attempt.Author)
		}
		head, err := loadHead(ctx, tx, attempt.ID)
		if err != nil {
			return err
		}
		targetID := p.Operation
		if targetID == "" {
			targetID = head
		}
		if targetID == "" {
			return fmt.Errorf("%w: the workspace has no operations", ErrNotUndoable)
		}
		target, err := loadOp(ctx, tx, targetID)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrUnknownOperation, targetID)
		}
		if target.Attempt != attempt.ID {
			return fmt.Errorf("%w: %s belongs to attempt %s", ErrUnknownOperation, targetID, target.Attempt)
		}

		switch target.Kind {
		case specv1.OperationOpen, specv1.OperationFork:
			return fmt.Errorf("%w: %s only creates the workspace", ErrNotUndoable, target.Kind)

		}
		if isWorldOp(target) {
			return s.revertWorld(ctx, tx, attempt, head, target, p.Author, key, &result)
		}

		// A file operation (or a revert of one): restore the path to its state
		// before the target.
		before, err := overlayAt(ctx, tx, target.Parent)
		if err != nil {
			return err
		}
		blob, present := before[target.Path]
		n := newOp{kind: specv1.OperationRevert, path: target.Path, reverts: target.ID, by: p.Author}
		switch {
		case !present:
			n.unset = true
		default:
			n.blob = blob // "" means it was deleted
		}
		result, err = appendOp(ctx, tx, attempt.ID, n, key)
		return err
	})
	if err != nil {
		return specv1.Operation{}, err
	}
	return result, nil
}

// revertWorld undoes a commit, or a revert of a commit, by restoring the world
// the attempt had before it.
func (s *Store) revertWorld(ctx context.Context, tx storage.Tx, attempt specv1.Attempt, head string, target specv1.Operation, by string, key ed25519.PrivateKey, out *specv1.Operation) error {
	if target.PrevWorld == nil {
		return fmt.Errorf("%w: %s did not change the world", ErrNotUndoable, target.ID)
	}
	// The target must be the latest operation that moved the world, and its
	// effect must still be in force.
	latest, err := latestWorldOp(ctx, tx, head, attempt.ID)
	if err != nil {
		return err
	}
	if latest != target.ID || target.World == nil || attempt.World != *target.World {
		return fmt.Errorf("%w: %s is not the latest change to the attempt's world, which is %s", ErrNotUndoable, target.ID, shortWorld(attempt.World))
	}

	current := attempt.World
	restored := *target.PrevWorld
	op, err := appendOp(ctx, tx, attempt.ID, newOp{kind: specv1.OperationRevert, reverts: target.ID, world: &restored, prevWorld: &current, by: by}, key)
	if err != nil {
		return err
	}
	attempt.World = restored
	if err = putAttemptState(ctx, tx, &attempt, key); err != nil {
		return err
	}
	*out = op
	return nil
}

// isWorldOp reports whether op changed the attempt's world: a commit, or the
// revert of one.
func isWorldOp(op specv1.Operation) bool {
	return op.Kind == specv1.OperationCommit || (op.Kind == specv1.OperationRevert && op.Path == "" && op.World != nil)
}

func shortWorld(w specv1.WorldHash) string { return w.String()[:12] }

// latestWorldOp finds the newest operation in attemptID's own log that changed
// the attempt's world.
func latestWorldOp(ctx context.Context, g getter, head, attemptID string) (string, error) {
	for id, steps := head, 0; id != "" && steps < maxLogWalk; steps++ {
		op, err := loadOp(ctx, g, id)
		if err != nil {
			return "", err
		}
		if op.Attempt != attemptID {
			return "", nil
		}
		if isWorldOp(op) {
			return op.ID, nil
		}
		id = op.Parent
	}
	return "", nil
}

// sortedPaths returns the keys of overlay in order.
func sortedPaths(overlay map[string]string) []string {
	paths := make([]string, 0, len(overlay))
	for p := range overlay {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
