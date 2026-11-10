// Package gitops drives the git binary for the few things meiosis needs from a
// repository: creating the bare repositories it serves, finding what a push
// changed, and hashing a commit's tree into a world (FR-2.2).
//
// It shells out to git rather than reimplementing the object model: git is the
// reference for its own formats, and the SRS budgets for a hand-written smart
// HTTP server on top of it, not a replacement for it (RK-6).
package gitops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/worlds"
)

// ZeroID is the all-zero object ID git uses for "no such object" in ref updates.
const ZeroID = "0000000000000000000000000000000000000000"

// IsZero reports whether id is an all-zero object ID of either hash length.
func IsZero(id string) bool {
	return id != "" && strings.Trim(id, "0") == ""
}

// Repo is a git repository driven through the git binary.
type Repo struct {
	// Dir is the repository (a bare repo's directory). Empty means "use the
	// GIT_DIR in the environment", which is what a hook run by git has.
	Dir string
	// Git is the git binary; empty means "git" on PATH.
	Git string
}

func (r Repo) cmd(ctx context.Context, args ...string) *exec.Cmd {
	bin := r.Git
	if bin == "" {
		bin = "git"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = os.Environ()
	if r.Dir != "" {
		cmd.Env = append(cmd.Env, "GIT_DIR="+r.Dir)
	}
	return cmd
}

func (r Repo) output(ctx context.Context, args ...string) ([]byte, error) {
	cmd := r.cmd(ctx, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// InitBare creates a bare repository at dir configured for serving over smart
// HTTP under meiosis's rules: receive-pack enabled, push options advertised (so
// a push can name its intent), and history rewriting and ref deletion refused.
// Calling it on an existing repository only re-applies the configuration.
func InitBare(ctx context.Context, git, dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	r := Repo{Dir: dir, Git: git}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		bin := git
		if bin == "" {
			bin = "git"
		}
		out, err := exec.CommandContext(ctx, bin, "init", "--bare", "--initial-branch=main", dir).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git init --bare: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	for _, kv := range [][2]string{
		{"http.receivepack", "true"},
		{"receive.advertisePushOptions", "true"},
		{"receive.denyNonFastForwards", "true"},
		{"receive.denyDeletes", "true"},
		{"uploadpack.allowFilter", "true"},
	} {
		if _, err := r.output(ctx, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// InstallHooks writes the pre-receive and post-receive hooks that hand each
// push to `<mei> hook ...`, where meiosis's policy runs. Existing hooks of
// those names are replaced.
func InstallHooks(dir, meiBinary string) error {
	hooks := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooks, 0o750); err != nil {
		return err
	}
	for _, name := range []string{"pre-receive", "post-receive"} {
		script := "#!/bin/sh\n# Installed by meiosis; replaced on every `mei serve`.\nexec " + shellQuote(meiBinary) + " hook " + name + "\n"
		if err := os.WriteFile(filepath.Join(hooks, name), []byte(script), 0o755); err != nil { //nolint:gosec // git requires hook scripts to be executable
			return fmt.Errorf("write %s hook: %w", name, err)
		}
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ChangedPaths lists, sorted and de-duplicated, every path touched by the
// commits a ref update introduces: oldID..newID, or, when the ref is new, the
// commits reachable from newID and from no other ref. Deleted paths are
// included, since removing a file is as much a write as changing one.
func (r Repo) ChangedPaths(ctx context.Context, ref, oldID, newID string) ([]string, error) {
	args := append([]string{"log", "--name-only", "--format=", "-z", "--no-renames", "-m"}, rangeArgs(ref, oldID, newID)...)
	out, err := r.output(ctx, args...)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) > 0 {
			seen[string(p)] = struct{}{}
		}
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// rangeArgs selects the commits a ref update introduces: oldID..newID, or, when
// the ref is new, those reachable from newID and from no other ref.
func rangeArgs(ref, oldID, newID string) []string {
	if !IsZero(oldID) && oldID != "" {
		return []string{oldID + ".." + newID}
	}
	// Not --all: that includes HEAD, which in a bare repository is a symbolic
	// ref to a branch and so would hide the very commits being introduced. An
	// exclude pattern given with --branches or --tags is relative to that
	// namespace.
	args := []string{newID, "--not"}
	if name, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		args = append(args, "--exclude="+name)
	}
	args = append(args, "--branches")
	if name, ok := strings.CutPrefix(ref, "refs/tags/"); ok {
		args = append(args, "--exclude="+name)
	}
	return append(args, "--tags")
}

// EachAddedLine calls fn for every line a ref update adds, with its path and its
// line number in the new file, reading at most maxBytes of diff. It reports
// whether the diff was longer than that and so was not read to the end. Binary
// files are skipped.
func (r Repo) EachAddedLine(ctx context.Context, ref, oldID, newID string, maxBytes int64, fn func(path string, line int, text string)) (truncated bool, err error) {
	args := append([]string{"-c", "core.quotepath=false", "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=", "-m", "--no-renames"}, rangeArgs(ref, oldID, newID)...)
	cmd := r.cmd(ctx, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return false, fmt.Errorf("git log -p: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1<<16), 4<<20)
	var (
		read   int64
		path   string
		inFile bool
		line   int
	)
	for scanner.Scan() {
		text := scanner.Text()
		read += int64(len(text)) + 1
		if read > maxBytes {
			truncated = true
			break
		}
		switch {
		case strings.HasPrefix(text, "diff --git "):
			path, inFile, line = "", false, 0
		case strings.HasPrefix(text, "+++ "):
			path, inFile = diffPath(strings.TrimPrefix(text, "+++ "))
		case strings.HasPrefix(text, "@@ "):
			line = hunkStart(text)
		case inFile && strings.HasPrefix(text, "+"):
			fn(path, line, text[1:])
			line++
		}
	}
	scanErr := scanner.Err()
	if truncated || scanErr != nil {
		_ = stdout.Close()
	}
	waitErr := cmd.Wait()
	switch {
	case scanErr != nil:
		return truncated, fmt.Errorf("read diff: %w", scanErr)
	case truncated:
		return true, nil // git was stopped on purpose
	case waitErr != nil:
		return false, fmt.Errorf("git log -p: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return false, nil
}

// diffPath extracts the path from a "+++ b/path" header; ok is false for a
// deletion (+++ /dev/null).
func diffPath(header string) (string, bool) {
	header = strings.TrimRight(header, "\t")
	if header == "/dev/null" {
		return "", false
	}
	if strings.HasPrefix(header, "\"") {
		if unq, err := strconv.Unquote(header); err == nil {
			header = unq
		}
	}
	return strings.TrimPrefix(header, "b/"), true
}

// hunkStart reads the first new-file line number from "@@ -a,b +c,d @@".
func hunkStart(header string) int {
	plus := strings.Index(header, " +")
	if plus < 0 {
		return 0
	}
	rest := header[plus+2:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}

// Subject returns the first line of a commit's message.
func (r Repo) Subject(ctx context.Context, commit string) (string, error) {
	out, err := r.output(ctx, "log", "-1", "--format=%s", commit)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ObjectType returns what kind of object id names ("commit", "tag", ...).
func (r Repo) ObjectType(ctx context.Context, id string) (string, error) {
	out, err := r.output(ctx, "cat-file", "-t", id)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

type treeEntry struct {
	mode, kind, oid, path string
}

// World hashes the tree at commit into a world hash, reading each blob once and
// streaming it into the hash, so memory stays flat however large the repository
// is. The hash is the one pkg/worlds gives the same files, so a tree produced by
// an attempt and the same tree pushed through git hash identically. File modes
// are not part of a world; a submodule contributes its commit ID.
func (r Repo) World(ctx context.Context, commit string) (specv1.WorldHash, int, error) {
	listing, err := r.output(ctx, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return specv1.WorldHash{}, 0, err
	}
	var entries []treeEntry
	for _, rec := range bytes.Split(listing, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, found := bytes.Cut(rec, []byte{'\t'})
		fields := strings.Fields(string(meta))
		if !found || len(fields) != 3 {
			return specv1.WorldHash{}, 0, fmt.Errorf("gitops: unexpected ls-tree record %q", rec)
		}
		entries = append(entries, treeEntry{mode: fields[0], kind: fields[1], oid: fields[2], path: string(path)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	hasher := worlds.NewHasher()
	if len(entries) == 0 {
		return hasher.Sum(), 0, nil
	}

	cat := r.cmd(ctx, "cat-file", "--batch")
	stdin, err := cat.StdinPipe()
	if err != nil {
		return specv1.WorldHash{}, 0, err
	}
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return specv1.WorldHash{}, 0, err
	}
	var stderr bytes.Buffer
	cat.Stderr = &stderr
	if err = cat.Start(); err != nil {
		return specv1.WorldHash{}, 0, fmt.Errorf("git cat-file: %w", err)
	}
	reader := bufio.NewReaderSize(stdout, 1<<16)
	finish := func(runErr error) error {
		_ = stdin.Close()
		waitErr := cat.Wait()
		if runErr != nil {
			return runErr
		}
		if waitErr != nil {
			return fmt.Errorf("git cat-file: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
		}
		return nil
	}

	for _, e := range entries {
		if e.kind == "commit" { // a submodule: no blob, only the commit it pins
			if err = hasher.Add(e.path, []byte("gitlink:"+e.oid)); err != nil {
				return specv1.WorldHash{}, 0, finish(err)
			}
			continue
		}
		if _, err = io.WriteString(stdin, e.oid+"\n"); err != nil {
			return specv1.WorldHash{}, 0, finish(err)
		}
		header, readErr := reader.ReadString('\n')
		if readErr != nil {
			return specv1.WorldHash{}, 0, finish(fmt.Errorf("read blob header for %q: %w", e.path, readErr))
		}
		parts := strings.Fields(header)
		if len(parts) != 3 {
			return specv1.WorldHash{}, 0, finish(fmt.Errorf("blob %s for %q: %s", e.oid, e.path, strings.TrimSpace(header)))
		}
		size, parseErr := strconv.ParseInt(parts[2], 10, 64)
		if parseErr != nil {
			return specv1.WorldHash{}, 0, finish(fmt.Errorf("blob %s: bad size %q", e.oid, parts[2]))
		}
		if err = hasher.AddStream(e.path, size, reader); err != nil {
			return specv1.WorldHash{}, 0, finish(err)
		}
		if _, err = reader.ReadByte(); err != nil { // the newline after the content
			return specv1.WorldHash{}, 0, finish(err)
		}
	}
	if err = finish(nil); err != nil {
		return specv1.WorldHash{}, 0, err
	}
	return hasher.Sum(), len(entries), nil
}

// ErrNoRepo is returned when a path is not a git repository.
var ErrNoRepo = errors.New("gitops: not a git repository")
