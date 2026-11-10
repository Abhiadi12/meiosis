package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

func params(title string) graph.CreateIntentParams {
	return graph.CreateIntentParams{
		Repo: "r", Title: title, Goal: "goal " + title,
		Acceptance: []specv1.Criterion{{Text: "ok"}},
		Scope:      specv1.Scope{Allow: []string{"src/**"}, Mode: specv1.ScopeModeEnforce},
		CreatedBy:  "human:lakin",
	}
}

func mustIntent(t *testing.T, env *attemptEnv, p graph.CreateIntentParams) specv1.Intent {
	t.Helper()
	intent, err := env.store.CreateIntent(context.Background(), p, env.keys.PrivateKey)
	if err != nil {
		t.Fatalf("CreateIntent(%s) error = %v", p.Title, err)
	}
	return intent
}

func TestCreateIntentCarriesParentDependenciesPinsAndNonGoals(t *testing.T) {
	env := newAttemptEnv(t)
	parent := mustIntent(t, env, params("parent"))
	dep := mustIntent(t, env, params("dep"))

	pin, err := graph.NewContextPin("docs/adr-1.md", specv1.ContextPinKindADR, []byte("decision"))
	if err != nil {
		t.Fatal(err)
	}
	p := params("child")
	p.Parent, p.DependsOn, p.ContextPins, p.NonGoals = parent.ID, []string{dep.ID, dep.ID}, []specv1.ContextPin{pin}, []string{"no refactors"}
	child := mustIntent(t, env, p)

	if child.Parent != parent.ID || len(child.DependsOn) != 1 || child.DependsOn[0] != dep.ID {
		t.Fatalf("links = parent %q deps %v, want deduplicated links preserved", child.Parent, child.DependsOn)
	}
	if len(child.ContextPins) != 1 || child.ContextPins[0].Digest != graph.PinDigest([]byte("decision")) || len(child.NonGoals) != 1 {
		t.Fatalf("pins/non-goals not stored: %+v", child)
	}
	got, err := env.store.GetIntent(context.Background(), child.ID)
	if err != nil || got.ID != child.ID {
		t.Fatalf("GetIntent() = %+v, %v", got, err)
	}
}

func TestCreateIntentRejectsUnknownReferences(t *testing.T) {
	env := newAttemptEnv(t)
	missing := "int_" + strings.Repeat("z", 52)
	p := params("child")
	p.DependsOn = []string{missing}
	if _, err := env.store.CreateIntent(context.Background(), p, env.keys.PrivateKey); !errors.Is(err, graph.ErrUnknownIntent) {
		t.Fatalf("unknown dependency error = %v, want ErrUnknownIntent", err)
	}
	p = params("child2")
	p.Parent = missing
	if _, err := env.store.CreateIntent(context.Background(), p, env.keys.PrivateKey); !errors.Is(err, graph.ErrUnknownIntent) {
		t.Fatalf("unknown parent error = %v, want ErrUnknownIntent", err)
	}
}

func TestSupersedeCannotCreateDependencyCycle(t *testing.T) {
	env := newAttemptEnv(t)
	a := mustIntent(t, env, params("A"))
	bp := params("B")
	bp.DependsOn = []string{a.ID}
	b := mustIntent(t, env, bp)

	// A' replaces A but depends on B, which depends on A: A' would depend on itself.
	ap := params("A prime")
	ap.DependsOn = []string{b.ID}
	if _, err := env.store.SupersedeIntent(context.Background(), a.ID, ap, env.keys.PrivateKey); !errors.Is(err, graph.ErrCycle) {
		t.Fatalf("direct cycle error = %v, want ErrCycle", err)
	}

	// A longer chain: C depends on B; A' depends on C.
	cp := params("C")
	cp.DependsOn = []string{b.ID}
	c := mustIntent(t, env, cp)
	ap2 := params("A prime 2")
	ap2.DependsOn = []string{c.ID}
	if _, err := env.store.SupersedeIntent(context.Background(), a.ID, ap2, env.keys.PrivateKey); !errors.Is(err, graph.ErrCycle) {
		t.Fatalf("transitive cycle error = %v, want ErrCycle", err)
	}

	// A rejected supersede leaves the predecessor untouched.
	view, err := env.store.GetIntentView(context.Background(), a.ID)
	if err != nil || view.SupersededBy != "" {
		t.Fatalf("predecessor after rejected supersede = %+v, %v", view, err)
	}

	// An acyclic successor is fine.
	if _, err := env.store.SupersedeIntent(context.Background(), a.ID, params("A prime ok"), env.keys.PrivateKey); err != nil {
		t.Fatalf("acyclic supersede rejected: %v", err)
	}
}

func TestSupersedeLeavesPredecessorImmutableAndClosesItToAttempts(t *testing.T) {
	env := newAttemptEnv(t)
	old := mustIntent(t, env, params("old"))
	before, _ := env.backend.Get(context.Background(), storage.KindIntent, old.ID)

	successor, err := env.store.SupersedeIntent(context.Background(), old.ID, params("new"), env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := env.backend.Get(context.Background(), storage.KindIntent, old.ID)
	if string(before) != string(after) {
		t.Fatal("the superseded intent's record was modified")
	}

	view, err := env.store.GetIntentView(context.Background(), old.ID)
	if err != nil || view.SupersededBy != successor.ID {
		t.Fatalf("view = %+v, %v; want SupersededBy %s", view, err, successor.ID)
	}
	if view.Status != specv1.IntentStatusOpen {
		t.Fatalf("immutable status changed: %s", view.Status)
	}

	_, err = env.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{Intent: old.ID, Author: "agent:impl"}, env.keys.PrivateKey)
	if !errors.Is(err, graph.ErrIntentClosed) || !strings.Contains(err.Error(), successor.ID) {
		t.Fatalf("OpenAttempt on a superseded intent = %v, want ErrIntentClosed naming the successor", err)
	}
	if _, err = env.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{Intent: successor.ID, Author: "agent:impl"}, env.keys.PrivateKey); err != nil {
		t.Fatalf("OpenAttempt on the successor: %v", err)
	}

	if _, err = env.store.SupersedeIntent(context.Background(), old.ID, params("again"), env.keys.PrivateKey); !errors.Is(err, graph.ErrAlreadySuperseded) {
		t.Fatalf("second supersede = %v, want ErrAlreadySuperseded", err)
	}
	if _, err = env.store.SupersedeIntent(context.Background(), "int_"+strings.Repeat("y", 52), params("x"), env.keys.PrivateKey); !errors.Is(err, graph.ErrUnknownIntent) {
		t.Fatalf("supersede unknown = %v, want ErrUnknownIntent", err)
	}
}

func TestOpeningAnAttemptMovesIntentToAttemptingAndStateIsSigned(t *testing.T) {
	env := newAttemptEnv(t)
	intent := mustIntent(t, env, params("work"))
	if v, _ := env.store.GetIntentView(context.Background(), intent.ID); v.CurrentStatus != specv1.IntentStatusOpen {
		t.Fatalf("fresh intent status = %s", v.CurrentStatus)
	}
	env.open(t, intent)
	view, err := env.store.GetIntentView(context.Background(), intent.ID)
	if err != nil || view.CurrentStatus != specv1.IntentStatusAttempting {
		t.Fatalf("status after opening an attempt = %s, %v; want attempting", view.CurrentStatus, err)
	}
	raw, _ := env.backend.Get(context.Background(), storage.KindIntentState, intent.ID)
	var state specv1.IntentState
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if ok, verr := crypto.Verify(state, state.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatalf("intent state signature invalid: %v, %v", ok, verr)
	}
	if _, err = env.store.OpenAttempt(context.Background(), graph.OpenAttemptParams{Intent: intent.ID, Author: "agent:b"}, env.keys.PrivateKey); err != nil {
		t.Fatalf("competitive second attempt rejected: %v", err)
	}
}

func TestListIntentViewsHidesSupersededByDefault(t *testing.T) {
	env := newAttemptEnv(t)
	old := mustIntent(t, env, params("old"))
	if _, err := env.store.SupersedeIntent(context.Background(), old.ID, params("new"), env.keys.PrivateKey); err != nil {
		t.Fatal(err)
	}
	live, _ := env.store.ListIntentViews(context.Background(), false)
	all, _ := env.store.ListIntentViews(context.Background(), true)
	if len(live) != 1 || live[0].Title != "new" || len(all) != 2 {
		t.Fatalf("live = %d (%v), all = %d", len(live), live, len(all))
	}
}

func TestDeriveIntentFromTaskNeedsNoAuthoring(t *testing.T) {
	env := newAttemptEnv(t)
	scope := specv1.Scope{Allow: []string{"src/**"}, Deny: []string{"src/secret/**"}, Mode: specv1.ScopeModeEnforce}
	task := "Fix the login redirect bug\n\nUsers land on /home instead of the page they asked for."

	intent, created, err := env.store.DeriveIntent(context.Background(), graph.DeriveIntentParams{Repo: "r", Task: task, Scope: scope, CreatedBy: "agent:impl"}, env.keys.PrivateKey)
	if err != nil || !created {
		t.Fatalf("DeriveIntent() = %v, created %v", err, created)
	}
	if intent.Title != "Fix the login redirect bug" || intent.Goal != strings.TrimSpace(task) || len(intent.Acceptance) != 1 || intent.CreatedBy != "agent:impl" {
		t.Fatalf("derived intent = %+v", intent)
	}
	if intent.Scope.Mode != specv1.ScopeModeEnforce || intent.Scope.Allow[0] != "src/**" || intent.Scope.Deny[0] != "src/secret/**" {
		t.Fatalf("derived scope = %+v, want the agent's own authority", intent.Scope)
	}
	if ok, verr := crypto.Verify(intent, intent.Signature, env.keys.PublicKey); verr != nil || !ok {
		t.Fatalf("derived intent signature invalid: %v, %v", ok, verr)
	}

	again, created, err := env.store.DeriveIntent(context.Background(), graph.DeriveIntentParams{Repo: "r", Task: task, Scope: scope, CreatedBy: "agent:impl"}, env.keys.PrivateKey)
	if err != nil || created || again.ID != intent.ID {
		t.Fatalf("re-deriving the same task = %v created=%v id=%s, want the existing intent", err, created, again.ID)
	}
	other, created, _ := env.store.DeriveIntent(context.Background(), graph.DeriveIntentParams{Repo: "r", Task: task, Scope: scope, CreatedBy: "agent:other"}, env.keys.PrivateKey)
	if !created || other.ID == intent.ID {
		t.Fatal("a different agent must get its own derived intent")
	}

	if _, _, err = env.store.DeriveIntent(context.Background(), graph.DeriveIntentParams{Repo: "r", Task: "  ", Scope: scope, CreatedBy: "agent:impl"}, env.keys.PrivateKey); !errors.Is(err, graph.ErrInvalidParams) {
		t.Fatalf("empty task error = %v, want ErrInvalidParams", err)
	}
}

func TestDeriveIntentTruncatesLongTitles(t *testing.T) {
	env := newAttemptEnv(t)
	intent, _, err := env.store.DeriveIntent(context.Background(), graph.DeriveIntentParams{
		Repo: "r", Task: strings.Repeat("word ", 60), Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeWarn}, CreatedBy: "agent:impl",
	}, env.keys.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(intent.Title)); n > 80 || !strings.HasSuffix(intent.Title, "…") {
		t.Fatalf("title = %q (%d runes), want <= 80 and ellipsised", intent.Title, n)
	}
}

func TestVerifyPinsDetectsChangedMissingAndUncheckable(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/spec.md", "v1")
	write("docs/gone.md", "x")
	pinSpec, _ := graph.NewContextPin("docs/spec.md", specv1.ContextPinKindSpec, []byte("v1"))
	pinGone, _ := graph.NewContextPin("docs/gone.md", specv1.ContextPinKindDesign, []byte("x"))
	pinURL, _ := graph.NewContextPin("https://example.com/adr", specv1.ContextPinKindADR, []byte("remote"))
	pinEscape, _ := graph.NewContextPin("../outside.md", specv1.ContextPinKindIssue, []byte("o"))
	pins := []specv1.ContextPin{pinSpec, pinGone, pinURL, pinEscape}

	status := func() map[string]graph.PinCheck {
		out := map[string]graph.PinCheck{}
		for _, c := range graph.VerifyPins(root, pins) {
			out[c.Ref] = c
		}
		return out
	}
	got := status()
	if got["docs/spec.md"].Status != graph.PinMatch || got["https://example.com/adr"].Status != graph.PinUnchecked || got["../outside.md"].Status != graph.PinUnchecked {
		t.Fatalf("initial = %+v", got)
	}

	write("docs/spec.md", "v2")
	if err := os.Remove(filepath.Join(root, "docs/gone.md")); err != nil {
		t.Fatal(err)
	}
	got = status()
	if got["docs/spec.md"].Status != graph.PinChanged || !got["docs/spec.md"].Stale() || got["docs/spec.md"].Current != graph.PinDigest([]byte("v2")) {
		t.Fatalf("changed pin = %+v", got["docs/spec.md"])
	}
	if got["docs/gone.md"].Status != graph.PinMissing || !got["docs/gone.md"].Stale() {
		t.Fatalf("missing pin = %+v", got["docs/gone.md"])
	}
}

func TestNewContextPinValidates(t *testing.T) {
	if _, err := graph.NewContextPin("", specv1.ContextPinKindSpec, nil); err == nil {
		t.Fatal("empty ref accepted")
	}
	if _, err := graph.NewContextPin("a.md", "bogus", nil); err == nil {
		t.Fatal("unknown kind accepted")
	}
}
