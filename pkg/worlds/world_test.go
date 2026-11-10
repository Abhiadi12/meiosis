package worlds

import (
	"context"
	"errors"
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestIdenticalTreesHaveIdenticalWorldHashes(t *testing.T) {
	left, err := NewMemoryTree(map[string][]byte{"a.txt": []byte("a"), "src/main.go": []byte("package main")})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewMemoryTree(map[string][]byte{"src/main.go": []byte("package main"), "a.txt": []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	first, err := New(context.Background(), left)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), right)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash() != second.Hash() {
		t.Fatalf("identical trees have different hashes: %s != %s", first.Hash(), second.Hash())
	}
}

func TestDifferentTreesHaveDifferentWorldHashes(t *testing.T) {
	left, err := NewMemoryTree(map[string][]byte{"file.txt": []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	right, err := left.WithFile("file.txt", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := New(context.Background(), left)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(context.Background(), right)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash() == second.Hash() {
		t.Fatal("different trees have the same hash")
	}
}

func TestSnapshotAndForkPreserveContent(t *testing.T) {
	tree, err := NewMemoryTree(map[string][]byte{"README.md": []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewMemorySnapshotter(tree)
	if err != nil {
		t.Fatal(err)
	}
	world, err := Snapshot(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	fork, err := world.Fork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if world.Hash() != fork.Hash() {
		t.Fatal("fork changed the content hash")
	}
	files, err := fork.Tree()
	if err != nil {
		t.Fatal(err)
	}
	content, err := files.Files(context.Background())
	if err != nil || string(content["README.md"]) != "hello" {
		t.Fatalf("fork content = %q, error = %v", content["README.md"], err)
	}
}

func TestWorldDiff(t *testing.T) {
	baseTree, err := NewMemoryTree(map[string][]byte{"same": []byte("same"), "changed": []byte("old"), "deleted": []byte("gone")})
	if err != nil {
		t.Fatal(err)
	}
	targetTree, err := NewMemoryTree(map[string][]byte{"same": []byte("same"), "changed": []byte("new"), "added": []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	base, err := New(context.Background(), baseTree)
	if err != nil {
		t.Fatal(err)
	}
	target, err := New(context.Background(), targetTree)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := base.Diff(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 {
		t.Fatalf("change count = %d, want 3", len(changes))
	}
	if changes[0].Path != "added" || changes[0].Kind != Added || changes[1].Path != "changed" || changes[1].Kind != Modified || changes[2].Path != "deleted" || changes[2].Kind != Deleted {
		t.Fatalf("changes = %+v, want sorted added/modified/deleted changes", changes)
	}
}

func TestWorldRejectsInvalidInput(t *testing.T) {
	if _, err := New(context.Background(), nil); !errors.Is(err, ErrNilTree) {
		t.Fatalf("New(nil) error = %v, want ErrNilTree", err)
	}
	if _, err := NewMemoryTree(map[string][]byte{"../secret": []byte("bad")}); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("NewMemoryTree() error = %v, want ErrInvalidPath", err)
	}
	var empty World
	if _, err := empty.Fork(context.Background()); !errors.Is(err, ErrMissingWorld) {
		t.Fatalf("Fork(empty) error = %v, want ErrMissingWorld", err)
	}
}

func TestWorldHashUsesSpecWorldHash(t *testing.T) {
	tree, err := NewMemoryTree(nil)
	if err != nil {
		t.Fatal(err)
	}
	world, err := New(context.Background(), tree)
	if err != nil {
		t.Fatal(err)
	}
	if world.Hash() == (specv1.WorldHash{}) {
		t.Fatal("empty tree produced zero WorldHash")
	}
}

func TestHasherMatchesNewForTheSameFiles(t *testing.T) {
	files := map[string][]byte{"a.go": []byte("A"), "dir/b.go": []byte("B"), "dir/sub/c": nil, "z": []byte("Z")}
	tree, err := NewMemoryTree(files)
	if err != nil {
		t.Fatal(err)
	}
	world, err := New(context.Background(), tree)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHasher()
	for _, p := range []string{"a.go", "dir/b.go", "dir/sub/c", "z"} {
		if err := h.Add(p, files[p]); err != nil {
			t.Fatal(err)
		}
	}
	if h.Sum() != world.Hash() {
		t.Fatalf("Hasher = %s, New = %s", h.Sum(), world.Hash())
	}
	if NewHasher().Sum() != EmptyTreeHash() {
		t.Fatal("the empty Hasher must equal the empty tree's hash")
	}
}

func TestHasherRejectsUnorderedAndInvalidPaths(t *testing.T) {
	h := NewHasher()
	if err := h.Add("b", nil); err != nil {
		t.Fatal(err)
	}
	if err := h.Add("a", nil); !errors.Is(err, ErrUnordered) {
		t.Fatalf("out-of-order Add = %v, want ErrUnordered", err)
	}
	if err := h.Add("b", nil); !errors.Is(err, ErrUnordered) {
		t.Fatalf("duplicate Add = %v, want ErrUnordered", err)
	}
	for _, bad := range []string{"", "/abs", "../x", `back\slash`} {
		if err := NewHasher().Add(bad, nil); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Add(%q) = %v, want ErrInvalidPath", bad, err)
		}
	}
}
