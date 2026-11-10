// Package worlds provides Meiosis-side world operations behind a replaceable
// tree backend boundary. The temporary in-memory backend in this package is
// only a development adapter; zygote/vfs will provide the production backend.
package worlds

import (
	"context"
	"errors"
)

// Errors returned by this package; test with errors.Is.
var (
	ErrNilTree      = errors.New("world tree must not be nil")
	ErrInvalidPath  = errors.New("invalid world path")
	ErrMissingWorld = errors.New("world is not initialized")
	ErrUnordered    = errors.New("world files must be added in increasing path order")
)

// Tree is the narrow boundary between Meiosis and a tree implementation such
// as the future zygote/vfs adapter. Implementations must return a snapshot of
// files and must not expose mutable internal byte slices.
type Tree interface {
	Files(context.Context) (map[string][]byte, error)
}

// ForkableTree is an optional extension for backends that can create a fork
// while preserving their own sharing strategy.
type ForkableTree interface {
	Tree
	Fork(context.Context) (Tree, error)
}

// Snapshotter creates a Tree snapshot from an external repository source.
type Snapshotter interface {
	Snapshot(context.Context) (Tree, error)
}

// ChangeKind identifies how a path differs between two worlds.
type ChangeKind string

// The kinds of change between two worlds.
const (
	Added    ChangeKind = "added"
	Modified ChangeKind = "modified"
	Deleted  ChangeKind = "deleted"
)

// Change describes one file-level difference between worlds.
type Change struct {
	Path   string
	Kind   ChangeKind
	Before []byte
	After  []byte
}
