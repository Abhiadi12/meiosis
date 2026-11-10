package graph_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func commitWithCost(env *attemptEnv, attempt specv1.Attempt, cost int64, limits ...graph.SpendLimit) (graph.CommitResult, error) {
	return env.store.CommitAttempt(context.Background(), graph.CommitParams{
		Attempt: attempt.ID, Author: "agent:impl", CostMicros: cost, SpendLimits: limits,
	}, env.keys.PrivateKey)
}

func TestCommitChargesEveryCeilingInTheChain(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	ctx := context.Background()
	child, parent := graph.SpendLimit{TokenID: "cap_child", CeilingMicros: 100}, graph.SpendLimit{TokenID: "cap_parent", CeilingMicros: 150}

	_, _ = env.write(attempt, "src/a.go", "A")
	if _, err := commitWithCost(env, attempt, 60, child, parent); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	for id, want := range map[string]int64{"cap_child": 60, "cap_parent": 60} {
		if got, _ := env.store.Spent(ctx, id); got != want {
			t.Errorf("Spent(%s) = %d, want %d", id, got, want)
		}
	}

	// A different token under the same parent spends from the parent's budget too.
	other := graph.SpendLimit{TokenID: "cap_other", CeilingMicros: 100}
	_, _ = env.write(attempt, "src/b.go", "B")
	if _, err := commitWithCost(env, attempt, 100, other, parent); err == nil || !errors.Is(err, identity.ErrSpendCeiling) {
		t.Fatalf("a commit that would pass the parent's ceiling (60+100 > 150) = %v, want ErrSpendCeiling", err)
	}
	// The refusal leaves nothing behind: no world change, no attestation, no spend.
	cur, _ := env.store.GetAttempt(ctx, attempt.ID)
	if cur.World == graph.EmptyWorld() {
		t.Fatal("the first commit's world was lost")
	}
	if got, _ := env.store.Spent(ctx, "cap_other"); got != 0 {
		t.Errorf("a refused commit charged cap_other %d", got)
	}
	if got, _ := env.store.Spent(ctx, "cap_parent"); got != 60 {
		t.Errorf("a refused commit changed the parent's spend to %d", got)
	}
	state, _ := env.store.GetAttempt(ctx, attempt.ID)
	if _, err := env.store.GetAttestation(ctx, attempt.ID, state.World); err != nil {
		t.Fatalf("the earlier attestation disappeared: %v", err)
	}

	// Within budget it goes through.
	if _, err := commitWithCost(env, attempt, 50, other, parent); err != nil {
		t.Fatalf("a commit within both ceilings: %v", err)
	}
	if got, _ := env.store.Spent(ctx, "cap_parent"); got != 110 {
		t.Errorf("Spent(cap_parent) = %d, want 110", got)
	}
}

func TestRecommitOfTheSameWorldIsNotBilledTwice(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	limit := graph.SpendLimit{TokenID: "cap_one", CeilingMicros: 100}
	_, _ = env.write(attempt, "src/a.go", "A")
	if _, err := commitWithCost(env, attempt, 90, limit); err != nil {
		t.Fatal(err)
	}
	if _, err := commitWithCost(env, attempt, 90, limit); err != nil {
		t.Fatalf("recommitting the identical world must not be charged again: %v", err)
	}
	if got, _ := env.store.Spent(context.Background(), "cap_one"); got != 90 {
		t.Fatalf("Spent = %d, want 90", got)
	}
}

func TestZeroCostCommitsAreFree(t *testing.T) {
	env := newAttemptEnv(t)
	attempt := openedAttempt(t, env)
	_, _ = env.write(attempt, "src/a.go", "A")
	if _, err := commitWithCost(env, attempt, 0, graph.SpendLimit{TokenID: "cap_zero", CeilingMicros: 0}); err != nil {
		t.Fatalf("a free commit under a zero ceiling: %v", err)
	}
	_, _ = env.write(attempt, "src/b.go", "B")
	if _, err := commitWithCost(env, attempt, 1, graph.SpendLimit{TokenID: "cap_zero", CeilingMicros: 0}); !errors.Is(err, identity.ErrSpendCeiling) {
		t.Fatalf("any cost under a zero ceiling = %v, want ErrSpendCeiling", err)
	}
}

func TestAuthorityRecordsKeepTheWholeChainAndAreQueryable(t *testing.T) {
	env := newAttemptEnv(t)
	human, _ := crypto.GenerateKeyPair()
	agentA, _ := crypto.GenerateKeyPair()
	agentB, _ := crypto.GenerateKeyPair()
	root, err := identity.Issue(identity.IssueParams{
		Principal: "agent:a", IssuedBy: "human:lakin", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}, HolderKey: agentA.PublicKey,
	}, human.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	child, err := identity.Delegate(root, identity.DelegateParams{Principal: "agent:b", HolderKey: agentB.PublicKey}, agentA.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	w, err := env.store.RecordAuthority(ctx, graph.AuthorityParams{Op: "attempt_write", Principal: "agent:b", Token: child, Object: "att_x", Attempt: "att_x", Path: "src/a.go"}, env.keys.PrivateKey)
	if err != nil {
		t.Fatalf("RecordAuthority() error = %v", err)
	}
	if ok, verr := crypto.Verify(w, w.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatalf("authority record signature invalid: %v, %v", ok, verr)
	}
	time.Sleep(time.Millisecond)
	if _, err = env.store.RecordAuthority(ctx, graph.AuthorityParams{Op: "evidence_ingest", Principal: "agent:a", Token: root, Object: "evd_y", Attempt: "att_x"}, env.keys.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err = env.store.RecordAuthority(ctx, graph.AuthorityParams{Op: "intent_create", Principal: "agent:a", Token: root, Object: "int_z", Intent: "int_z"}, env.keys.PrivateKey); err != nil {
		t.Fatal(err)
	}

	forAttempt, err := env.store.ListAuthority(ctx, "att_x")
	if err != nil || len(forAttempt) != 2 || forAttempt[0].Op != "attempt_write" || forAttempt[1].Op != "evidence_ingest" {
		t.Fatalf("ListAuthority(att_x) = %+v, %v; want the write then the evidence, oldest first", forAttempt, err)
	}
	// The chain to the originating human is recoverable from the record alone.
	links := identity.Links(forAttempt[0].Token)
	if len(links) != 2 || links[0].Principal != "agent:b" || identity.Origin(forAttempt[0].Token) != "human:lakin" {
		t.Fatalf("recorded chain = %+v origin %s", links, identity.Origin(forAttempt[0].Token))
	}
	if err = identity.Verify(forAttempt[0].Token, human.PublicKey, nil, time.Now()); err != nil {
		t.Fatalf("the recorded chain no longer verifies against the issuer: %v", err)
	}
	if byObject, _ := env.store.ListAuthority(ctx, "evd_y"); len(byObject) != 1 {
		t.Fatalf("ListAuthority(evd_y) = %d records", len(byObject))
	}
	if byIntent, _ := env.store.ListAuthority(ctx, "int_z"); len(byIntent) != 1 {
		t.Fatalf("ListAuthority(int_z) = %d records", len(byIntent))
	}
	if all, _ := env.store.ListAuthority(ctx, ""); len(all) != 3 {
		t.Fatalf("ListAuthority(\"\") = %d records, want 3", len(all))
	}
	if _, err = env.store.RecordAuthority(ctx, graph.AuthorityParams{Op: "not_an_op", Principal: "agent:a", Token: root}, env.keys.PrivateKey); !errors.Is(err, graph.ErrInvalidParams) {
		t.Fatalf("an unknown operation was recorded: %v", err)
	}
}
