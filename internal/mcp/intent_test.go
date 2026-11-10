package mcp

import (
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func intentArgs(title string, extra map[string]any) map[string]any {
	args := map[string]any{
		"repo": "r", "title": title, "goal": "goal " + title,
		"acceptance": []map[string]any{{"text": "ok"}},
		"scope":      map[string]any{"allow": []string{"src/**"}, "mode": "enforce"},
	}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

func TestIntentCreateAcceptsLinksAndPinsGivenAsContentOrDigest(t *testing.T) {
	s := newTestServer(t)
	parent, errText := call(t, s, "intent_create", intentArgs("parent", nil))
	if errText != "" {
		t.Fatal(errText)
	}
	digest := graph.PinDigest([]byte("adr text"))
	child, errText := call(t, s, "intent_create", intentArgs("child", map[string]any{
		"parent": parent["id"], "depends_on": []string{parent["id"].(string)}, "non_goals": []string{"no refactor"},
		"context_pins": []map[string]any{
			{"ref": "docs/a.md", "kind": "adr", "content": "adr text"},
			{"ref": "https://x/y", "kind": "design", "digest": digest},
		},
	}))
	if errText != "" {
		t.Fatalf("intent_create with links and pins: %s", errText)
	}
	pins, _ := child["context_pins"].([]any)
	if len(pins) != 2 || pins[0].(map[string]any)["digest"] != digest {
		t.Fatalf("context_pins = %v, want both pinned with the same digest", child["context_pins"])
	}

	_, errText = call(t, s, "intent_create", intentArgs("bad", map[string]any{"depends_on": []string{"int_" + strings.Repeat("q", 52)}}))
	if !strings.Contains(errText, "unknown intent") {
		t.Fatalf("unknown dependency error = %q", errText)
	}
	_, errText = call(t, s, "intent_create", intentArgs("bad2", map[string]any{
		"context_pins": []map[string]any{{"ref": "a", "digest": digest, "content": "x"}},
	}))
	if !strings.Contains(errText, "digest or content") {
		t.Fatalf("digest+content error = %q", errText)
	}
}

func TestIntentGetListAndSupersedeThroughMCP(t *testing.T) {
	s := newTestServer(t)
	old, _ := call(t, s, "intent_create", intentArgs("old", nil))

	got, errText := call(t, s, "intent_get", map[string]any{"intent": old["id"]})
	if errText != "" || got["current_status"] != "open" || got["title"] != "old" {
		t.Fatalf("intent_get = %v %s", got, errText)
	}
	if _, errText = call(t, s, "intent_get", map[string]any{"intent": "int_" + strings.Repeat("q", 52)}); errText == "" {
		t.Fatal("intent_get on an unknown intent succeeded")
	}

	sup, errText := call(t, s, "intent_supersede", withIntent(intentArgs("new", nil), old["id"]))
	if errText != "" {
		t.Fatalf("intent_supersede: %s", errText)
	}
	successor := sup["successor"].(map[string]any)

	got, _ = call(t, s, "intent_get", map[string]any{"intent": old["id"]})
	if got["superseded_by"] != successor["id"] {
		t.Fatalf("predecessor = %v, want superseded_by %v", got, successor["id"])
	}
	list, _ := call(t, s, "intent_list", map[string]any{})
	if n := len(list["intents"].([]any)); n != 1 {
		t.Fatalf("intent_list = %d intents, want only the live one", n)
	}
	list, _ = call(t, s, "intent_list", map[string]any{"include_superseded": true})
	if n := len(list["intents"].([]any)); n != 2 {
		t.Fatalf("intent_list(include_superseded) = %d intents, want 2", n)
	}

	_, errText = call(t, s, "attempt_open", map[string]any{"intent": old["id"]})
	if !strings.Contains(errText, "superseded by") {
		t.Fatalf("attempt on superseded intent = %q", errText)
	}
}

func withIntent(args map[string]any, id any) map[string]any {
	args["intent"] = id
	return args
}

func TestIntentListShowsBoundTokenOnlyItsOwnIntent(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	a := declareIntent(t, s, repoToken, "enforce")
	_, errText := call(t, s, "intent_create", withToken(intentArgs("second", nil), tokenArg(t, repoToken)))
	if errText != "" {
		t.Fatal(errText)
	}

	bound := issueToken(t, issuer, s.Principal, a)
	list, errText := call(t, s, "intent_list", map[string]any{"capability_token": tokenArg(t, bound)})
	if errText != "" {
		t.Fatal(errText)
	}
	if n := len(list["intents"].([]any)); n != 1 {
		t.Fatalf("bound token sees %d intents, want 1", n)
	}
	list, _ = call(t, s, "intent_list", map[string]any{"capability_token": tokenArg(t, repoToken)})
	if n := len(list["intents"].([]any)); n != 2 {
		t.Fatalf("repo token sees %d intents, want 2", n)
	}

	// A bound token cannot read or supersede other intents.
	other, _ := call(t, s, "intent_list", map[string]any{"capability_token": tokenArg(t, repoToken)})
	var otherID string
	for _, i := range other["intents"].([]any) {
		if id := i.(map[string]any)["id"].(string); id != a {
			otherID = id
		}
	}
	if _, errText = call(t, s, "intent_get", map[string]any{"intent": otherID, "capability_token": tokenArg(t, bound)}); !strings.Contains(errText, "different intent") {
		t.Fatalf("bound token reading another intent = %q", errText)
	}
	args := withToken(withIntent(intentArgs("x", nil), a), tokenArg(t, bound))
	if _, errText = call(t, s, "intent_supersede", args); !strings.Contains(errText, "cannot create new intents") {
		t.Fatalf("bound token superseding = %q", errText)
	}
}

func withToken(args map[string]any, token any) map[string]any {
	args["capability_token"] = token
	return args
}

// FR-3.8: an agent given only a task gets an intent without authoring one.
func TestAttemptOpenFromTaskDerivesIntentFromTokenAuthority(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	tok := tokenArg(t, repoToken)

	opened, errText := call(t, s, "attempt_open", map[string]any{"task": "Fix the login redirect\n\nmore detail", "capability_token": tok})
	if errText != "" {
		t.Fatalf("attempt_open(task): %s", errText)
	}
	if opened["derived_intent"] != true || opened["intent_title"] != "Fix the login redirect" || opened["id"] == nil {
		t.Fatalf("result = %v, want a derived intent and an open attempt", opened)
	}

	intent, errText := call(t, s, "intent_get", map[string]any{"intent": opened["intent"], "capability_token": tok})
	if errText != "" {
		t.Fatal(errText)
	}
	if intent["created_by"] != s.Principal || intent["current_status"] != "attempting" {
		t.Fatalf("derived intent = %v", intent)
	}
	scope := intent["scope"].(map[string]any)
	if scope["mode"] != "enforce" || scope["allow"].([]any)[0] != "**" {
		t.Fatalf("derived scope = %v, want the token's authority", scope)
	}

	again, _ := call(t, s, "attempt_open", map[string]any{"task": "Fix the login redirect\n\nmore detail", "capability_token": tok})
	if again["derived_intent"] != false || again["intent"] != opened["intent"] {
		t.Fatalf("second open for the same task = %v, want the same intent reused", again)
	}
}

func TestAttemptOpenFromTaskNarrowTokenScopeBecomesIntentScope(t *testing.T) {
	s, issuer := enforcingServer(t)
	narrow := mustIssue(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent, specv1.Scope{Allow: []string{"src/**"}, Deny: []string{"src/secret/**"}, Mode: specv1.ScopeModeEnforce})
	opened, errText := call(t, s, "attempt_open", map[string]any{"task": "Tidy src", "capability_token": tokenArg(t, narrow)})
	if errText != "" {
		t.Fatal(errText)
	}
	// A write the token's own scope permits but the derived intent's scope
	// (inherited from the token) does not would indicate a scope mismatch; both
	// must reject the same paths.
	for _, path := range []string{"docs/x.md", "src/secret/k"} {
		_, errText = call(t, s, "attempt_write", map[string]any{"attempt": opened["id"], "path": path, "content": "x", "capability_token": tokenArg(t, narrow)})
		if errText == "" {
			t.Fatalf("write to %s accepted, want rejection", path)
		}
	}
	if _, errText = call(t, s, "attempt_write", map[string]any{"attempt": opened["id"], "path": "src/ok.go", "content": "x", "capability_token": tokenArg(t, narrow)}); errText != "" {
		t.Fatalf("in-scope write rejected: %s", errText)
	}
}

func TestAttemptOpenNeedsExactlyOneOfIntentOrTask(t *testing.T) {
	s := newTestServer(t)
	for _, args := range []map[string]any{{}, {"intent": "int_x", "task": "do it"}} {
		if _, errText := call(t, s, "attempt_open", args); !strings.Contains(errText, "exactly one of intent") {
			t.Fatalf("attempt_open(%v) error = %q", args, errText)
		}
	}
	// Without enforcement an agent still needs only a task.
	opened, errText := call(t, s, "attempt_open", map[string]any{"task": "just do it"})
	if errText != "" || opened["derived_intent"] != true {
		t.Fatalf("attempt_open(task) without enforcement = %v %s", opened, errText)
	}
}

func TestBoundTokenCannotDeriveIntents(t *testing.T) {
	s, issuer := enforcingServer(t)
	repoToken := issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent)
	id := declareIntent(t, s, repoToken, "enforce")
	bound := issueToken(t, issuer, s.Principal, id)
	_, errText := call(t, s, "attempt_open", map[string]any{"task": "sneaky", "capability_token": tokenArg(t, bound)})
	if !strings.Contains(errText, "cannot derive new intents") {
		t.Fatalf("error = %q", errText)
	}
}
