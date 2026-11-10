package v1

import (
	"strings"
	"time"
)

// OperationKind names what an Operation did to a workspace.
type OperationKind string

const (
	OperationOpen   OperationKind = "open"   // the workspace was created
	OperationWrite  OperationKind = "write"  // a file was written
	OperationDelete OperationKind = "delete" // a file was deleted
	OperationCommit OperationKind = "commit" // the workspace was snapshotted into a world
	OperationFork   OperationKind = "fork"   // the workspace was created from another's state
	OperationRevert OperationKind = "revert" // an earlier operation was undone
)

// SnapshotInterval is how often an operation carries a full snapshot of the
// workspace, which bounds how many operations must be read to know its state.
const SnapshotInterval = 32

// Operation is one entry in a workspace's operation log (FR-2.5). The log is
// append-only and every operation is signed by the principal that made it, so a
// workspace's history, including its undos, can be audited and replayed.
//
// A workspace's state is an overlay on its attempt's base world: a map from
// path to the blob holding the file's content, where the empty string means the
// file is deleted and an absent path means it is as in the base. The state at an
// operation is that overlay after applying the log up to it. Because an
// operation names only its parent, forking a workspace (FR-2.3) is one new
// operation pointing at the source's latest one: constant time whatever the size
// of the tree or of the overlay.
type Operation struct {
	ID      string        `json:"id"` // "op_" + base32(blake3(canonical))
	Attempt string        `json:"attempt"`
	Kind    OperationKind `json:"kind"`
	// Seq is this operation's distance from the start of its lineage, which
	// continues across a fork.
	Seq    int    `json:"seq"`
	Parent string `json:"parent,omitempty"` // the previous operation; absent for the first

	Path string `json:"path,omitempty"` // write, delete, revert of a file operation
	Blob string `json:"blob,omitempty"` // write: the content's blob ID; revert: the content restored
	// Unset, on a revert, returns Path to its state in the base world (no overlay
	// entry), as opposed to an empty Blob, which means deleted.
	Unset bool `json:"unset,omitempty"`

	// Reverts names the operation a revert undoes.
	Reverts string `json:"reverts,omitempty"`
	// ForkedFrom names the attempt a fork was taken from.
	ForkedFrom string `json:"forked_from,omitempty"`

	// World is the world a commit produced, or the world a revert of a commit
	// restored. PrevWorld is the attempt's world before this operation, which is
	// what undoing it brings back.
	World     *WorldHash `json:"world,omitempty"`
	PrevWorld *WorldHash `json:"prev_world,omitempty"`

	// Snapshot, present every SnapshotInterval operations, is the complete
	// overlay after this operation.
	Snapshot map[string]string `json:"snapshot,omitempty"`

	By        string    `json:"by"`
	At        time.Time `json:"at"`
	Signature string    `json:"signature"`
}

func (o Operation) Validate() error {
	if !validContentID(o.ID, "op_") || !validContentID(o.Attempt, "att_") || !validPrincipalID(o.By) || o.At.IsZero() || strings.TrimSpace(o.Signature) == "" || o.Seq < 0 {
		return ErrInvalidOperation
	}
	if o.Parent != "" && !validContentID(o.Parent, "op_") {
		return ErrInvalidOperation
	}
	if (o.Parent == "") != (o.Seq == 0) {
		return ErrInvalidOperation // exactly the first operation of a lineage has no parent
	}
	for _, w := range []*WorldHash{o.World, o.PrevWorld} {
		if w != nil && w.Validate() != nil {
			return ErrInvalidOperation
		}
	}
	switch o.Kind {
	case OperationOpen:
		if o.Seq != 0 {
			return ErrInvalidOperation
		}
	case OperationWrite:
		if strings.TrimSpace(o.Path) == "" || o.Blob == "" {
			return ErrInvalidOperation
		}
	case OperationDelete:
		if strings.TrimSpace(o.Path) == "" || o.Blob != "" {
			return ErrInvalidOperation
		}
	case OperationCommit:
		if o.World == nil || o.PrevWorld == nil {
			return ErrInvalidOperation
		}
	case OperationFork:
		if !validContentID(o.ForkedFrom, "att_") || o.Parent == "" {
			return ErrInvalidOperation
		}
	case OperationRevert:
		if !validContentID(o.Reverts, "op_") {
			return ErrInvalidOperation
		}
		file := strings.TrimSpace(o.Path) != ""
		world := o.World != nil
		if file == world || (o.Unset && o.Blob != "") || (world && (o.Unset || o.Blob != "")) {
			return ErrInvalidOperation // a revert restores either one file or the world, not both
		}
	default:
		return ErrInvalidOperation
	}
	if o.Kind != OperationWrite && o.Kind != OperationRevert && o.Blob != "" {
		return ErrInvalidOperation
	}
	return nil
}
