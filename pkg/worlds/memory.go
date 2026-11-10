package worlds

import (
	"context"
	"fmt"
	"sort"
)

// MemoryTree is a temporary immutable development adapter. It intentionally
// provides no structural-sharing guarantees; zygote/vfs will own that concern.
type MemoryTree struct {
	files map[string][]byte
}

// NewMemoryTree creates a validated in-memory tree from file contents.
func NewMemoryTree(files map[string][]byte) (*MemoryTree, error) {
	copyFiles := make(map[string][]byte, len(files))
	for filePath, content := range files {
		if err := validatePath(filePath); err != nil {
			return nil, err
		}
		copyFiles[filePath] = cloneBytes(content)
	}
	return &MemoryTree{files: copyFiles}, nil
}

// Files returns a copy of the tree's files, keyed by path.
func (t *MemoryTree) Files(context.Context) (map[string][]byte, error) {
	if t == nil {
		return nil, ErrNilTree
	}
	files := make(map[string][]byte, len(t.files))
	for filePath, content := range t.files {
		files[filePath] = cloneBytes(content)
	}
	return files, nil
}

// WithFile returns a new temporary tree with content at filePath replaced.
func (t *MemoryTree) WithFile(filePath string, content []byte) (*MemoryTree, error) {
	if t == nil {
		return nil, ErrNilTree
	}
	if err := validatePath(filePath); err != nil {
		return nil, err
	}
	files, err := t.Files(context.Background())
	if err != nil {
		return nil, err
	}
	files[filePath] = cloneBytes(content)
	return NewMemoryTree(files)
}

// WithoutFile returns a new temporary tree without filePath.
func (t *MemoryTree) WithoutFile(filePath string) (*MemoryTree, error) {
	if t == nil {
		return nil, ErrNilTree
	}
	if err := validatePath(filePath); err != nil {
		return nil, err
	}
	files, err := t.Files(context.Background())
	if err != nil {
		return nil, err
	}
	delete(files, filePath)
	return NewMemoryTree(files)
}

// Fork returns an independent temporary tree with the same content.
func (t *MemoryTree) Fork(ctx context.Context) (Tree, error) {
	files, err := t.Files(ctx)
	if err != nil {
		return nil, err
	}
	return NewMemoryTree(files)
}

// MemorySnapshotter is a temporary snapshot source for tests and local
// development. A repository-backed adapter can replace it later.
type MemorySnapshotter struct {
	tree *MemoryTree
}

// NewMemorySnapshotter creates a temporary snapshot source from a tree.
func NewMemorySnapshotter(tree *MemoryTree) (*MemorySnapshotter, error) {
	if tree == nil {
		return nil, ErrNilTree
	}
	return &MemorySnapshotter{tree: tree}, nil
}

// Snapshot returns the files of the tree it was created from.
func (s *MemorySnapshotter) Snapshot(ctx context.Context) (Tree, error) {
	if s == nil || s.tree == nil {
		return nil, ErrNilTree
	}
	return s.tree.Fork(ctx)
}

// FilesList returns paths in deterministic order for callers inspecting the
// temporary adapter in tests.
func (t *MemoryTree) FilesList(ctx context.Context) ([]string, error) {
	files, err := t.Files(ctx)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for filePath := range files {
		paths = append(paths, filePath)
	}
	sort.Strings(paths)
	return paths, nil
}

func (t *MemoryTree) String() string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("MemoryTree(%d files)", len(t.files))
}

var (
	_ ForkableTree = (*MemoryTree)(nil)
	_ Snapshotter  = (*MemorySnapshotter)(nil)
)
