package worlds

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/zeebo/blake3"
)

// World is an immutable Meiosis snapshot. Tree implementations own their
// storage strategy; structural sharing remains outside this package.
type World struct {
	tree Tree
	hash specv1.WorldHash
}

// New creates a world from a tree snapshot and computes its deterministic
// BLAKE3-256 WorldHash.
func New(ctx context.Context, tree Tree) (World, error) {
	if tree == nil {
		return World{}, ErrNilTree
	}
	files, err := tree.Files(ctx)
	if err != nil {
		return World{}, fmt.Errorf("read world tree: %w", err)
	}
	hash, err := hashFiles(files)
	if err != nil {
		return World{}, err
	}
	return World{tree: tree, hash: hash}, nil
}

// Snapshot obtains a tree from source and creates a world from it.
func Snapshot(ctx context.Context, source Snapshotter) (World, error) {
	if source == nil {
		return World{}, ErrNilTree
	}
	tree, err := source.Snapshot(ctx)
	if err != nil {
		return World{}, fmt.Errorf("snapshot world: %w", err)
	}
	return New(ctx, tree)
}

// Hash returns the content address of the world.
func (w World) Hash() specv1.WorldHash {
	return w.hash
}

// Tree returns the backend tree associated with the world.
func (w World) Tree() (Tree, error) {
	if w.tree == nil {
		return nil, ErrMissingWorld
	}
	return w.tree, nil
}

// Fork creates a new snapshot with the same content. A production Tree may
// implement its own fork operation and structural sharing behind this API.
func (w World) Fork(ctx context.Context) (World, error) {
	if w.tree == nil {
		return World{}, ErrMissingWorld
	}
	if forkable, ok := w.tree.(ForkableTree); ok {
		tree, err := forkable.Fork(ctx)
		if err != nil {
			return World{}, fmt.Errorf("fork world tree: %w", err)
		}
		return New(ctx, tree)
	}
	return New(ctx, w.tree)
}

// Diff returns deterministic file-level changes from w to other.
func (w World) Diff(ctx context.Context, other World) ([]Change, error) {
	if w.tree == nil || other.tree == nil {
		return nil, ErrMissingWorld
	}
	before, err := w.tree.Files(ctx)
	if err != nil {
		return nil, fmt.Errorf("read base world: %w", err)
	}
	after, err := other.tree.Files(ctx)
	if err != nil {
		return nil, fmt.Errorf("read target world: %w", err)
	}
	paths := make(map[string]struct{}, len(before)+len(after))
	for filePath := range before {
		paths[filePath] = struct{}{}
	}
	for filePath := range after {
		paths[filePath] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for filePath := range paths {
		ordered = append(ordered, filePath)
	}
	sort.Strings(ordered)

	changes := make([]Change, 0)
	for _, filePath := range ordered {
		oldValue, existedBefore := before[filePath]
		newValue, existsAfter := after[filePath]
		switch {
		case !existedBefore:
			changes = append(changes, Change{Path: filePath, Kind: Added, After: cloneBytes(newValue)})
		case !existsAfter:
			changes = append(changes, Change{Path: filePath, Kind: Deleted, Before: cloneBytes(oldValue)})
		case !bytes.Equal(oldValue, newValue):
			changes = append(changes, Change{Path: filePath, Kind: Modified, Before: cloneBytes(oldValue), After: cloneBytes(newValue)})
		}
	}
	return changes, nil
}

func hashFiles(files map[string][]byte) (specv1.WorldHash, error) {
	paths := make([]string, 0, len(files))
	for filePath := range files {
		paths = append(paths, filePath)
	}
	sort.Strings(paths)
	hasher := NewHasher()
	for _, filePath := range paths {
		if err := hasher.Add(filePath, files[filePath]); err != nil {
			return specv1.WorldHash{}, err
		}
	}
	return hasher.Sum(), nil
}

// Hasher computes a world hash incrementally, one file at a time, so a large
// tree can be hashed without holding it in memory. Feeding it the files of a
// tree in order gives exactly the hash New gives for that tree: the encoding is
// a temporary one until zygote/vfs owns production Merkle-tree semantics.
type Hasher struct {
	hasher *blake3.Hasher
	last   string
	count  int
}

// EmptyTreeHash is the world hash of a tree with no files.
func EmptyTreeHash() specv1.WorldHash { return NewHasher().Sum() }

// NewHasher returns an empty Hasher.
func NewHasher() *Hasher { return &Hasher{hasher: blake3.New()} }

// Add hashes one file. Paths must be valid and added in strictly increasing
// byte order, which makes the result independent of how the caller walked the
// tree.
func (h *Hasher) Add(filePath string, content []byte) error {
	if err := validatePath(filePath); err != nil {
		return err
	}
	if h.count > 0 && filePath <= h.last {
		return fmt.Errorf("%w: %q is not after %q", ErrUnordered, filePath, h.last)
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(filePath)))
	_, _ = h.hasher.Write(length[:])
	_, _ = h.hasher.Write([]byte(filePath))
	binary.BigEndian.PutUint64(length[:], uint64(len(content)))
	_, _ = h.hasher.Write(length[:])
	_, _ = h.hasher.Write(content)
	h.last = filePath
	h.count++
	return nil
}

// AddStream is Add for content that is read rather than held: size bytes are
// copied from r straight into the hash, so a large file never sits in memory.
func (h *Hasher) AddStream(filePath string, size int64, r io.Reader) error {
	if err := validatePath(filePath); err != nil {
		return err
	}
	if h.count > 0 && filePath <= h.last {
		return fmt.Errorf("%w: %q is not after %q", ErrUnordered, filePath, h.last)
	}
	if size < 0 {
		return fmt.Errorf("worlds: negative size for %q", filePath)
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(filePath)))
	_, _ = h.hasher.Write(length[:])
	_, _ = h.hasher.Write([]byte(filePath))
	binary.BigEndian.PutUint64(length[:], uint64(size))
	_, _ = h.hasher.Write(length[:])
	if n, err := io.CopyN(h.hasher, r, size); err != nil {
		return fmt.Errorf("worlds: read %q: got %d of %d bytes: %w", filePath, n, size, err)
	}
	h.last = filePath
	h.count++
	return nil
}

// Sum returns the world hash of the files added so far.
func (h *Hasher) Sum() specv1.WorldHash {
	var hash specv1.WorldHash
	copy(hash[:], h.hasher.Sum(nil))
	return hash
}

func validatePath(filePath string) error {
	if !specv1.ValidRepoPath(filePath) {
		return fmt.Errorf("%w: %q", ErrInvalidPath, filePath)
	}
	return nil
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
