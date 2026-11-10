package gitops

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/pkg/worlds"
)

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newRepo(t *testing.T) (dir string, repo Repo) {
	t.Helper()
	needGit(t)
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	return dir, Repo{Dir: filepath.Join(dir, ".git")}
}

func commit(t *testing.T, dir, msg string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
	return git(t, dir, "rev-parse", "HEAD")
}

func TestChangedPathsForUpdatesNewRefsDeletionsAndOddNames(t *testing.T) {
	dir, repo := newRepo(t)
	ctx := context.Background()
	write(t, dir, "a.go", "1")
	write(t, dir, "d/b.go", "2")
	c1 := commit(t, dir, "first")
	write(t, dir, "a.go", "changed")
	write(t, dir, "sp ace/new file.txt", "x")
	write(t, dir, "ünï.txt", "x")
	if err := os.Remove(filepath.Join(dir, "d", "b.go")); err != nil {
		t.Fatal(err)
	}
	c2 := commit(t, dir, "second")

	got, err := repo.ChangedPaths(ctx, "refs/heads/main", c1, c2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.go", "d/b.go", "sp ace/new file.txt", "ünï.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ChangedPaths(update) = %q, want %q (a deletion is a change, names are not mangled)", got, want)
	}

	// A new ref introduces the commits no other ref already holds.
	git(t, dir, "branch", "release", c1)
	git(t, dir, "checkout", "-q", "-b", "topic", c1)
	write(t, dir, "topic-only.txt", "t")
	c4 := commit(t, dir, "topic work")
	got, err = repo.ChangedPaths(ctx, "refs/heads/topic", ZeroID, c4)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"topic-only.txt"}) {
		t.Fatalf("ChangedPaths(new ref) = %q, want only the paths of commits no other ref has", got)
	}
}

func TestChangedPathsIncludesAMergesPaths(t *testing.T) {
	dir, repo := newRepo(t)
	write(t, dir, "base", "b")
	base := commit(t, dir, "base")
	git(t, dir, "checkout", "-q", "-b", "side")
	write(t, dir, "side.txt", "s")
	commit(t, dir, "side")
	git(t, dir, "checkout", "-q", "main")
	write(t, dir, "main.txt", "m")
	commit(t, dir, "main")
	git(t, dir, "merge", "-q", "--no-edit", "side")
	tip := git(t, dir, "rev-parse", "HEAD")
	got, err := repo.ChangedPaths(context.Background(), "refs/heads/main", base, tip)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"main.txt", "side.txt"}) {
		t.Fatalf("ChangedPaths(merge) = %q", got)
	}
}

func TestWorldEqualsTheHashOfTheSameFilesInMemory(t *testing.T) {
	dir, repo := newRepo(t)
	files := map[string]string{
		"a.go": "package a", "d/b.go": "package b", "d/e/c.txt": strings.Repeat("c", 5000),
		"sp ace/x y": "spaced", "empty": "", "Z": "upper", "a-b": "dash", "a0": "zero",
	}
	for name, content := range files {
		write(t, dir, name, content)
	}
	tip := commit(t, dir, "files")

	got, n, err := repo.World(context.Background(), tip)
	if err != nil {
		t.Fatal(err)
	}
	mem := map[string][]byte{}
	for name, content := range files {
		mem[name] = []byte(content)
	}
	tree, err := worlds.NewMemoryTree(mem)
	if err != nil {
		t.Fatal(err)
	}
	want, err := worlds.New(context.Background(), tree)
	if err != nil {
		t.Fatal(err)
	}
	if got != want.Hash() || n != len(files) {
		t.Fatalf("World = %s (%d files), want %s (%d files): a pushed tree must hash like the same files in an attempt", got, n, want.Hash(), len(files))
	}
}

func TestWorldIgnoresModesAndChangesWithContent(t *testing.T) {
	dir, repo := newRepo(t)
	ctx := context.Background()
	write(t, dir, "run.sh", "#!/bin/sh\n")
	c1 := commit(t, dir, "one")
	w1, _, _ := repo.World(ctx, c1)

	git(t, dir, "update-index", "--chmod=+x", "run.sh")
	git(t, dir, "commit", "-q", "-m", "chmod")
	w2, _, _ := repo.World(ctx, git(t, dir, "rev-parse", "HEAD"))
	if w1 != w2 {
		t.Fatal("a mode change alone changed the world hash; worlds hash content")
	}

	write(t, dir, "run.sh", "#!/bin/sh\necho hi\n")
	w3, _, _ := repo.World(ctx, commit(t, dir, "edit"))
	if w3 == w1 {
		t.Fatal("changed content produced the same world hash")
	}
}

func TestWorldOfAnEmptyTreeAndWithASymlink(t *testing.T) {
	dir, repo := newRepo(t)
	ctx := context.Background()
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "empty")
	w, n, err := repo.World(ctx, git(t, dir, "rev-parse", "HEAD"))
	if err != nil || n != 0 || w != worlds.EmptyTreeHash() {
		t.Fatalf("empty tree World = %s, %d, %v", w, n, err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	write(t, dir, "target", "t")
	if _, _, err := repo.World(ctx, commit(t, dir, "link")); err != nil {
		t.Fatalf("a symlink should hash as its target text: %v", err)
	}
}

func TestWorldStreamsALargeBlobWithoutHoldingItAll(t *testing.T) {
	dir, repo := newRepo(t)
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<20) // 16 MiB
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "small", "s")
	tip := commit(t, dir, "big")
	got, _, err := repo.World(context.Background(), tip)
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := worlds.NewMemoryTree(map[string][]byte{"big.bin": big, "small": []byte("s")})
	want, _ := worlds.New(context.Background(), tree)
	if got != want.Hash() {
		t.Fatalf("large-file World = %s, want %s", got, want.Hash())
	}
}

func TestWorldOfAnUnknownCommitFails(t *testing.T) {
	_, repo := newRepo(t)
	if _, _, err := repo.World(context.Background(), strings.Repeat("a", 40)); err == nil {
		t.Fatal("World of a commit that does not exist succeeded")
	}
}

func TestSubjectAndObjectType(t *testing.T) {
	dir, repo := newRepo(t)
	write(t, dir, "f", "x")
	tip := commit(t, dir, "Fix the thing\n\nbody")
	if s, err := repo.Subject(context.Background(), tip); err != nil || s != "Fix the thing" {
		t.Fatalf("Subject = %q, %v", s, err)
	}
	if k, err := repo.ObjectType(context.Background(), tip); err != nil || k != "commit" {
		t.Fatalf("ObjectType = %q, %v", k, err)
	}
}

func TestInitBareConfiguresServingRulesAndIsIdempotent(t *testing.T) {
	needGit(t)
	dir := filepath.Join(t.TempDir(), "repos", "demo.git")
	ctx := context.Background()
	for i := range 2 {
		if err := InitBare(ctx, "", dir); err != nil {
			t.Fatalf("InitBare #%d: %v", i+1, err)
		}
	}
	r := Repo{Dir: dir}
	for key, want := range map[string]string{
		"http.receivepack": "true", "receive.advertisePushOptions": "true",
		"receive.denyNonFastForwards": "true", "receive.denyDeletes": "true",
	} {
		out, err := r.output(ctx, "config", "--get", key)
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Errorf("config %s = %q, %v; want %s", key, out, err, want)
		}
	}
	head, _ := os.ReadFile(filepath.Join(dir, "HEAD"))
	if !strings.Contains(string(head), "refs/heads/main") {
		t.Errorf("HEAD = %q, want main", head)
	}
}

func TestInstallHooksWritesExecutableScriptsThatQuoteThePath(t *testing.T) {
	needGit(t)
	dir := filepath.Join(t.TempDir(), "demo.git")
	if err := InitBare(context.Background(), "", dir); err != nil {
		t.Fatal(err)
	}
	if err := InstallHooks(dir, "/opt/it's here/mei"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pre-receive", "post-receive"} {
		info, err := os.Stat(filepath.Join(dir, "hooks", name))
		if err != nil || info.Mode().Perm()&0o100 == 0 {
			t.Fatalf("%s hook missing or not executable: %v", name, err)
		}
		body, _ := os.ReadFile(filepath.Join(dir, "hooks", name))
		if !strings.Contains(string(body), `exec '/opt/it'\''s here/mei' hook `+name) {
			t.Errorf("%s hook = %q", name, body)
		}
	}
}

func TestIsZero(t *testing.T) {
	for id, want := range map[string]bool{ZeroID: true, strings.Repeat("0", 64): true, "": false, strings.Repeat("a", 40): false, "0000000000000000000000000000000000000001": false} {
		if IsZero(id) != want {
			t.Errorf("IsZero(%q) = %t", id, !want)
		}
	}
}

type added struct {
	path string
	line int
	text string
}

func collectAdded(t *testing.T, repo Repo, ref, oldID, newID string, max int64) ([]added, bool) {
	t.Helper()
	var got []added
	truncated, err := repo.EachAddedLine(context.Background(), ref, oldID, newID, max, func(p string, line int, text string) {
		got = append(got, added{p, line, text})
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, truncated
}

func TestEachAddedLineReportsPathLineAndTextOfOnlyAddedLines(t *testing.T) {
	dir, repo := newRepo(t)
	write(t, dir, "a.go", "one\ntwo\nthree\n")
	write(t, dir, "dir with space/b.txt", "keep\n")
	c1 := commit(t, dir, "first")
	write(t, dir, "a.go", "one\nTWO\nthree\nfour\n")
	write(t, dir, "ünï/c.txt", "new\nfile\n")
	if err := os.Remove(filepath.Join(dir, "dir with space", "b.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin.dat"), []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := commit(t, dir, "second")

	got, truncated := collectAdded(t, repo, "refs/heads/main", c1, c2, 1<<20)
	if truncated {
		t.Fatal("truncated")
	}
	want := []added{{"a.go", 2, "TWO"}, {"a.go", 4, "four"}, {"ünï/c.txt", 1, "new"}, {"ünï/c.txt", 2, "file"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("added lines =\n%v\nwant\n%v (deleted files and binary files add nothing; line numbers are in the new file)", got, want)
	}
}

func TestEachAddedLineForANewRefSeesOnlyItsOwnCommitsAndHonoursTheLimit(t *testing.T) {
	dir, repo := newRepo(t)
	write(t, dir, "base.txt", "base\n")
	base := commit(t, dir, "base")
	git(t, dir, "checkout", "-q", "-b", "topic", base)
	var lines []string
	for range 500 {
		lines = append(lines, "added line number "+strings.Repeat("x", 40))
	}
	write(t, dir, "big.txt", strings.Join(lines, "\n")+"\n")
	tip := commit(t, dir, "topic work")

	got, truncated := collectAdded(t, repo, "refs/heads/topic", ZeroID, tip, 1<<20)
	if truncated || len(got) != 500 || got[0].path != "big.txt" {
		t.Fatalf("new ref: %d lines, truncated %t; want only big.txt's 500", len(got), truncated)
	}
	got, truncated = collectAdded(t, repo, "refs/heads/topic", ZeroID, tip, 2000)
	if !truncated || len(got) == 0 || len(got) >= 500 {
		t.Fatalf("with a 2000 byte limit: %d lines, truncated %t; want a partial read reported as truncated", len(got), truncated)
	}
}
