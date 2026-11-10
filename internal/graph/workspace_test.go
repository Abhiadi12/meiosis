package graph_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func (e *attemptEnv) overlay(t *testing.T, attempt specv1.Attempt) map[string]string {
	t.Helper()
	o, err := e.store.Workspace(context.Background(), attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func (e *attemptEnv) content(t *testing.T, blob string) string {
	t.Helper()
	data, err := e.backend.GetBlob(context.Background(), storageBlob(blob))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (e *attemptEnv) delete(attempt specv1.Attempt, path string) error {
	_, err := e.store.WriteFile(context.Background(), graph.WriteParams{Attempt: attempt.ID, Author: "agent:impl", Path: path, Delete: true}, e.keys.PrivateKey)
	return err
}

func (e *attemptEnv) undo(attempt specv1.Attempt, op string) (specv1.Operation, error) {
	return e.store.RevertOperation(context.Background(), graph.RevertParams{Attempt: attempt.ID, Author: "agent:impl", Operation: op}, e.keys.PrivateKey)
}

func (e *attemptEnv) commit(t *testing.T, attempt specv1.Attempt) specv1.Attempt {
	t.Helper()
	res, err := e.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: attempt.ID, Author: "agent:impl"}, e.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return res.Attempt
}

func TestEveryWorkspaceActionIsASignedOperationInAnAppendOnlyLog(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	_, _ = env.write(attempt, "src/a.go", "A")
	_ = env.delete(attempt, "src/a.go")
	env.commit(t, attempt)

	ops, err := env.store.ListOperations(context.Background(), attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, op := range ops {
		kinds = append(kinds, string(op.Kind))
		if ok, verr := crypto.Verify(op, op.Signature, env.keys.PublicKey); verr != nil || !ok {
			t.Errorf("operation %s: signature invalid (%v)", op.ID, verr)
		}
	}
	if got := strings.Join(kinds, ","); got != "commit,delete,write,open" {
		t.Fatalf("log (newest first) = %s, want commit,delete,write,open", got)
	}
	for i := 0; i < len(ops)-1; i++ {
		if ops[i].Parent != ops[i+1].ID || ops[i].Seq != ops[i+1].Seq+1 {
			t.Errorf("operations are not a chain at %d: %+v", i, ops[i])
		}
	}
	if ops[0].World == nil || ops[0].PrevWorld == nil || *ops[0].PrevWorld != graph.EmptyWorld() {
		t.Errorf("a commit records the world it produced and the one before: %+v", ops[0])
	}
}

func TestLongHistoriesReadThroughSnapshotsAndStillResolveCorrectly(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	want := map[string]string{}
	for i := 0; i < 3*specv1.SnapshotInterval+5; i++ {
		path := fmt.Sprintf("src/f%d.go", i%40) // overwrites, so history matters
		content := fmt.Sprintf("version %d", i)
		if _, err := env.write(attempt, path, content); err != nil {
			t.Fatal(err)
		}
		want[path] = content
		if i%7 == 3 {
			p := fmt.Sprintf("src/f%d.go", (i+11)%40)
			if err := env.delete(attempt, p); err != nil {
				t.Fatal(err)
			}
			want[p] = ""
		}
	}
	overlay := env.overlay(t, attempt)
	if len(overlay) != len(want) {
		t.Fatalf("overlay has %d paths, want %d", len(overlay), len(want))
	}
	for path, content := range want {
		got := overlay[path]
		if content == "" && got != "" || content != "" && env.content(t, got) != content {
			t.Errorf("%s resolved to %q, want %q", path, got, content)
		}
	}

	ops, _ := env.store.ListOperations(context.Background(), attempt.ID)
	snapshots := 0
	for _, op := range ops {
		if op.Snapshot != nil {
			snapshots++
			if op.Seq%specv1.SnapshotInterval != 0 {
				t.Errorf("a snapshot at Seq %d", op.Seq)
			}
		}
	}
	if snapshots < 3 {
		t.Fatalf("snapshots = %d, want one per %d operations", snapshots, specv1.SnapshotInterval)
	}
}

func TestForkIsAnIndependentCopyOfTheWorkspaceNotACopyOfTheData(t *testing.T) {
	env := newAttemptEnv(t)
	source := openedAttempt(t, env)
	_, _ = env.write(source, "src/a.go", "A")
	_, _ = env.write(source, "src/b.go", "B")
	sourceWorld := env.commit(t, source).World

	fork, err := env.store.ForkAttempt(context.Background(), graph.ForkParams{Source: source.ID, Author: "agent:other"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatalf("ForkAttempt: %v", err)
	}
	if fork.ForkedFrom != source.ID || fork.Intent != source.Intent || fork.BaseWorld != source.BaseWorld || fork.Author != "agent:other" || fork.ID == source.ID {
		t.Fatalf("fork = %+v", fork)
	}
	if ok, verr := crypto.Verify(fork, fork.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatalf("the fork is not signed: %v", verr)
	}

	// It starts with the source's files...
	if a, b := env.overlay(t, source), env.overlay(t, fork); len(b) != 2 || a["src/a.go"] != b["src/a.go"] || a["src/b.go"] != b["src/b.go"] {
		t.Fatalf("fork overlay = %v, source = %v", b, a)
	}
	// ...and, untouched, commits to exactly the source's world.
	res, err := env.store.CommitAttempt(context.Background(), graph.CommitParams{Attempt: fork.ID, Author: "agent:other"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if res.Attempt.World != sourceWorld {
		t.Fatalf("an unchanged fork committed to %s, want the source's %s: identical files must hash identically", res.Attempt.World, sourceWorld)
	}

	// Afterwards they diverge independently.
	if _, err = env.store.WriteFile(context.Background(), graph.WriteParams{Attempt: fork.ID, Author: "agent:other", Path: "src/only-fork.go", Content: []byte("F")}, env.keys.PrivateKey); err != nil {
		t.Fatal(err)
	}
	_, _ = env.write(source, "src/only-source.go", "S")
	if o := env.overlay(t, source); o["src/only-fork.go"] != "" || o["src/only-source.go"] == "" {
		t.Errorf("source overlay = %v", o)
	}
	if o := env.overlay(t, fork); o["src/only-source.go"] != "" || o["src/only-fork.go"] == "" {
		t.Errorf("fork overlay = %v", o)
	}
	// The fork's own log is its own: it holds the fork and what followed, not the source's history.
	forkOps, _ := env.store.ListOperations(context.Background(), fork.ID)
	var kinds []string
	for _, op := range forkOps {
		kinds = append(kinds, string(op.Kind))
	}
	if strings.Join(kinds, ",") != "write,commit,fork" {
		t.Fatalf("fork log = %v", kinds)
	}
	sourceOps, _ := env.store.ListOperations(context.Background(), source.ID)
	if len(sourceOps) != 5 { // open, write, write, commit, write
		t.Fatalf("source log has %d operations, want 5", len(sourceOps))
	}
}

// FR-2.3: the cost of a fork does not depend on how big the workspace is. The
// structural proof: forking a workspace with hundreds of files adds exactly the
// records forking an empty one does.
func TestForkCostIsIndependentOfWorkspaceSize(t *testing.T) {
	env := newAttemptEnv(t)
	intent := env.intent(t, specv1.ScopeModeEnforce)
	small, big := env.open(t, intent), env.open(t, intent)
	for i := 0; i < 600; i++ {
		if _, err := env.write(big, fmt.Sprintf("src/dir%d/file%d.go", i%30, i), "x"); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		n := 0
		for _, kind := range []string{"operations"} {
			recs, _ := env.backend.List(context.Background(), storageKind(kind))
			n += len(recs)
		}
		attempts, _ := env.backend.List(context.Background(), storageKind("attempts"))
		return n + len(attempts)
	}
	for name, src := range map[string]specv1.Attempt{"empty workspace": small, "600-file workspace": big} {
		before := count()
		if _, err := env.store.ForkAttempt(context.Background(), graph.ForkParams{Source: src.ID, Author: "agent:impl"}, env.keys.PrivateKey); err != nil {
			t.Fatal(err)
		}
		if added := count() - before; added != 2 { // the new attempt and its one fork operation
			t.Errorf("%s: a fork wrote %d records, want 2", name, added)
		}
	}
}

func TestForkRefusesAClosedIntentAndAnUnknownAttempt(t *testing.T) {
	env := newAttemptEnv(t)
	intent := env.intent(t, specv1.ScopeModeEnforce)
	source := env.open(t, intent)
	if _, err := env.store.ForkAttempt(context.Background(), graph.ForkParams{Source: "att_" + strings.Repeat("z", 52), Author: "agent:impl"}, env.keys.PrivateKey); err == nil {
		t.Fatal("forked an unknown attempt")
	}
	if _, err := env.store.SupersedeIntent(context.Background(), intent.ID, params("successor"), env.keys.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.ForkAttempt(context.Background(), graph.ForkParams{Source: source.ID, Author: "agent:impl"}, env.keys.PrivateKey); !errors.Is(err, graph.ErrIntentClosed) {
		t.Fatalf("forking under a superseded intent = %v, want ErrIntentClosed", err)
	}
}

func TestUndoPutsAPathBackAsItWas(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	_, _ = env.write(attempt, "src/a.go", "v1")
	_, _ = env.write(attempt, "src/a.go", "v2")

	op, err := env.undo(attempt, "")
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if op.Kind != specv1.OperationRevert || op.Path != "src/a.go" {
		t.Fatalf("op = %+v", op)
	}
	if got := env.content(t, env.overlay(t, attempt)["src/a.go"]); got != "v1" {
		t.Fatalf("after undo a.go = %q, want v1", got)
	}
	// The history is kept, not erased: the log grew.
	if ops, _ := env.store.ListOperations(context.Background(), attempt.ID); len(ops) != 4 {
		t.Fatalf("log has %d operations, want 4 (open, 2 writes, 1 revert)", len(ops))
	}

	// Undoing the undo is a redo.
	if _, err = env.undo(attempt, ""); err != nil {
		t.Fatal(err)
	}
	if got := env.content(t, env.overlay(t, attempt)["src/a.go"]); got != "v2" {
		t.Fatalf("after redo a.go = %q, want v2", got)
	}

	// Undoing the first write returns the path to its base state: no overlay entry at all.
	ops, _ := env.store.ListOperations(context.Background(), attempt.ID)
	first := ops[len(ops)-2] // the oldest write
	if _, err = env.undo(attempt, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, present := env.overlay(t, attempt)["src/a.go"]; present {
		t.Fatal("reverting the only first write should leave the path untouched, not deleted")
	}
}

func TestUndoRestoresADeletedFile(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	_, _ = env.write(attempt, "src/a.go", "keep me")
	_ = env.delete(attempt, "src/a.go")
	if env.overlay(t, attempt)["src/a.go"] != "" {
		t.Fatal("not deleted")
	}
	if _, err := env.undo(attempt, ""); err != nil {
		t.Fatal(err)
	}
	if got := env.content(t, env.overlay(t, attempt)["src/a.go"]); got != "keep me" {
		t.Fatalf("a.go = %q", got)
	}
}

func TestAnEarlierOperationCanBeUndoneWithoutDisturbingLaterOnes(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	_, _ = env.write(attempt, "src/a.go", "A1")
	_, _ = env.write(attempt, "src/b.go", "B1")
	_, _ = env.write(attempt, "src/c.go", "C1")
	ops, _ := env.store.ListOperations(context.Background(), attempt.ID)
	var writeB string
	for _, op := range ops {
		if op.Path == "src/b.go" {
			writeB = op.ID
		}
	}
	if _, err := env.undo(attempt, writeB); err != nil {
		t.Fatal(err)
	}
	o := env.overlay(t, attempt)
	if _, present := o["src/b.go"]; present || env.content(t, o["src/a.go"]) != "A1" || env.content(t, o["src/c.go"]) != "C1" {
		t.Fatalf("overlay = %v: only b.go should have gone", o)
	}
}

func TestUndoRefusesWhatCannotBeUndone(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	other := openedAttempt(t, env)
	ops, _ := env.store.ListOperations(context.Background(), attempt.ID)
	otherOps, _ := env.store.ListOperations(context.Background(), other.ID)

	if _, err := env.undo(attempt, ops[0].ID); !errors.Is(err, graph.ErrNotUndoable) {
		t.Errorf("undoing the open operation = %v, want ErrNotUndoable", err)
	}
	if _, err := env.undo(attempt, otherOps[0].ID); !errors.Is(err, graph.ErrUnknownOperation) {
		t.Errorf("undoing another attempt's operation = %v, want ErrUnknownOperation", err)
	}
	if _, err := env.undo(attempt, "op_"+strings.Repeat("z", 52)); !errors.Is(err, graph.ErrUnknownOperation) {
		t.Errorf("undoing an unknown operation = %v, want ErrUnknownOperation", err)
	}
	_, err := env.store.RevertOperation(context.Background(), graph.RevertParams{Attempt: attempt.ID, Author: "agent:intruder"}, env.keys.PrivateKey)
	if !errors.Is(err, graph.ErrNotAuthor) {
		t.Errorf("someone else undoing = %v, want ErrNotAuthor", err)
	}
}

// FR-2.6: undo restores the exact prior world hash and re-links the evidence
// that was bound to it.
func TestUndoingACommitRestoresTheExactPriorWorldAndRelinksItsEvidence(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	ctx := context.Background()
	_, _ = env.write(attempt, "src/a.go", "v1")
	w1 := env.commit(t, attempt)

	// Evidence is produced against that world.
	ev, err := env.store.SubmitEvidence(ctx, graph.SubmitEvidenceParams{
		Attempt: attempt.ID, Producer: "agent:ci", World: w1.World, Kind: specv1.EvidenceKindTestRun,
		Outcome: specv1.EvidenceOutcomePass, Payload: []byte(`{"tests":1}`),
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = env.write(attempt, "src/a.go", "v2")
	w2 := env.commit(t, attempt)
	if w2.World == w1.World {
		t.Fatal("world did not change")
	}
	standing := func() graph.EvidenceSummary {
		cur, _ := env.store.GetAttempt(ctx, attempt.ID)
		report, rerr := graph.BuildAttemptReport(ctx, env.store, cur)
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, e := range report.Evidence {
			if e.ID == ev.ID {
				return e
			}
		}
		t.Fatal("evidence missing")
		return graph.EvidenceSummary{}
	}
	if s := standing(); s.Fresh || s.Counted {
		t.Fatalf("evidence for the earlier world should be stale after the second commit: %+v", s)
	}

	op, err := env.undo(attempt, "")
	if err != nil {
		t.Fatalf("undo commit: %v", err)
	}
	cur, _ := env.store.GetAttempt(ctx, attempt.ID)
	if cur.World != w1.World {
		t.Fatalf("world after undo = %s, want exactly the earlier %s", cur.World, w1.World)
	}
	if op.World == nil || *op.World != w1.World || op.PrevWorld == nil || *op.PrevWorld != w2.World {
		t.Fatalf("the revert should record both worlds: %+v", op)
	}
	if s := standing(); !s.Fresh || !s.Counted {
		t.Fatalf("the evidence bound to the restored world must count again: %+v", s)
	}
	if ok, verr := crypto.Verify(cur, cur.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatal("the restored attempt state is not signed")
	}
	if _, err = env.store.GetAttestation(ctx, attempt.ID, w1.World); err != nil {
		t.Fatalf("the earlier world's provenance disappeared: %v", err)
	}

	// Redo: undoing the undo returns to the second world.
	if _, err = env.undo(attempt, ""); err != nil {
		t.Fatal(err)
	}
	if cur, _ = env.store.GetAttempt(ctx, attempt.ID); cur.World != w2.World {
		t.Fatalf("after redo world = %s, want %s", cur.World, w2.World)
	}
}

func TestOnlyTheLatestCommitCanBeUndone(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	_, _ = env.write(attempt, "src/a.go", "v1")
	env.commit(t, attempt)
	_, _ = env.write(attempt, "src/a.go", "v2")
	env.commit(t, attempt)

	ops, _ := env.store.ListOperations(context.Background(), attempt.ID)
	var commits []string
	for _, op := range ops {
		if op.Kind == specv1.OperationCommit {
			commits = append(commits, op.ID)
		}
	}
	if len(commits) != 2 {
		t.Fatalf("commits = %d", len(commits))
	}
	// commits[0] is the newest. The older one is not the attempt's current world.
	if _, err := env.undo(attempt, commits[1]); !errors.Is(err, graph.ErrNotUndoable) {
		t.Fatalf("undoing the older commit = %v, want ErrNotUndoable", err)
	}
	if _, err := env.undo(attempt, commits[0]); err != nil {
		t.Fatalf("undoing the newer commit: %v", err)
	}
	// Now the older one is the latest world operation... but only once the
	// revert has itself been dealt with: the latest is the revert.
	if _, err := env.undo(attempt, commits[1]); !errors.Is(err, graph.ErrNotUndoable) {
		t.Fatalf("undoing the older commit while a revert sits above it = %v, want ErrNotUndoable", err)
	}
}

func TestOperationValidation(t *testing.T) {
	w := specv1.MustParseWorldHash(strings.Repeat("ab", 32))
	base := specv1.Operation{
		ID: "op_" + strings.Repeat("a", 52), Attempt: "att_" + strings.Repeat("b", 52), Kind: specv1.OperationWrite,
		Seq: 1, Parent: "op_" + strings.Repeat("c", 52), Path: "a", Blob: "ff", By: "agent:x",
		At: mustTime(), Signature: "sig",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("a valid write: %v", err)
	}
	mutate := func(f func(*specv1.Operation)) specv1.Operation { o := base; f(&o); return o }
	for name, o := range map[string]specv1.Operation{
		"write without a blob":  mutate(func(o *specv1.Operation) { o.Blob = "" }),
		"write without a path":  mutate(func(o *specv1.Operation) { o.Path = "" }),
		"delete with a blob":    mutate(func(o *specv1.Operation) { o.Kind = specv1.OperationDelete }),
		"parentless but seq>0":  mutate(func(o *specv1.Operation) { o.Parent = "" }),
		"seq 0 with a parent":   mutate(func(o *specv1.Operation) { o.Seq = 0 }),
		"commit without worlds": mutate(func(o *specv1.Operation) { o.Kind, o.Path, o.Blob = specv1.OperationCommit, "", "" }),
		"fork without a source": mutate(func(o *specv1.Operation) { o.Kind, o.Path, o.Blob = specv1.OperationFork, "", "" }),
		"revert of nothing":     mutate(func(o *specv1.Operation) { o.Kind, o.Blob = specv1.OperationRevert, "" }),
		"revert of file and world": mutate(func(o *specv1.Operation) {
			o.Kind, o.Blob, o.Reverts, o.World = specv1.OperationRevert, "", "op_"+strings.Repeat("d", 52), &w
		}),
		"unset with a blob": mutate(func(o *specv1.Operation) {
			o.Kind, o.Reverts, o.Unset = specv1.OperationRevert, "op_"+strings.Repeat("d", 52), true
		}),
		"unknown kind":  mutate(func(o *specv1.Operation) { o.Kind = "frobnicate" }),
		"unsigned":      mutate(func(o *specv1.Operation) { o.Signature = "" }),
		"open at seq 1": mutate(func(o *specv1.Operation) { o.Kind, o.Path, o.Blob = specv1.OperationOpen, "", "" }),
	} {
		if err := o.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
