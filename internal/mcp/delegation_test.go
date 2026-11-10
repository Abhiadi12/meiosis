package mcp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// delegationEnv is an enforcing daemon running as agent:impl-3, whose key is
// the holder of the root token the human issued, plus a way to start a
// second daemon for a sub-agent that shares the same repository.
type delegationEnv struct {
	t      *testing.T
	parent *Server
	issuer crypto.KeyPair
	root   specv1.CapabilityToken
}

func newDelegationEnv(t *testing.T, mutate func(*identity.IssueParams)) *delegationEnv {
	t.Helper()
	s, issuer := enforcingServer(t)
	p := identity.IssueParams{
		Principal: s.Principal, IssuedBy: "human:lakin", Intent: specv1.CapabilityTokenAnyIntent,
		Scope:     specv1.Scope{Allow: []string{"src/**", "docs/**"}, Deny: []string{"src/secret/**"}, Mode: specv1.ScopeModeEnforce},
		HolderKey: s.Key.Public().(ed25519.PublicKey), TTL: time.Hour,
	}
	if mutate != nil {
		mutate(&p)
	}
	root, err := identity.Issue(p, issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &delegationEnv{t: t, parent: s, issuer: issuer, root: root}
}

// subAgent starts a daemon for principal sharing the parent's repository and
// trust, with its own key.
func (e *delegationEnv) subAgent(principal string) (*Server, crypto.KeyPair) {
	e.t.Helper()
	key, err := crypto.GenerateKeyPair()
	if err != nil {
		e.t.Fatal(err)
	}
	sub := NewServer(e.parent.Graph, principal, key.PrivateKey)
	sub.IssuerKey = e.parent.IssuerKey
	return sub, key
}

func (e *delegationEnv) tok(token specv1.CapabilityToken) any {
	e.t.Helper()
	enc, err := identity.Encode(token)
	if err != nil {
		e.t.Fatal(err)
	}
	return tokenArg(e.t, enc)
}

// delegate calls capability_delegate on the parent daemon.
func (e *delegationEnv) delegate(parent specv1.CapabilityToken, args map[string]any) (specv1.CapabilityToken, string) {
	e.t.Helper()
	args["capability_token"] = e.tok(parent)
	out, errText := call(e.t, e.parent, "capability_delegate", args)
	if errText != "" {
		return specv1.CapabilityToken{}, errText
	}
	raw, _ := json.Marshal(out["token"])
	var child specv1.CapabilityToken
	if err := json.Unmarshal(raw, &child); err != nil {
		e.t.Fatal(err)
	}
	return child, ""
}

func pubB64(k crypto.KeyPair) string { return base64.StdEncoding.EncodeToString(k.PublicKey) }

func TestAgentDelegatesANarrowerTokenToASubAgentWhoUsesIt(t *testing.T) {
	e := newDelegationEnv(t, nil)
	sub, subKey := e.subAgent("agent:tests-1")

	child, errText := e.delegate(e.root, map[string]any{
		"principal": "agent:tests-1", "holder_key": pubB64(subKey),
		"scope":      map[string]any{"allow": []string{"src/auth/**"}, "deny": []string{"src/secret/**"}, "mode": "enforce"},
		"operations": []string{"attempt_open", "attempt_write", "attempt_commit"},
	})
	if errText != "" {
		t.Fatalf("capability_delegate: %s", errText)
	}
	if child.Parent == nil || child.Parent.ID != e.root.ID || child.IssuedBy != e.parent.Principal || child.Depth() != 1 {
		t.Fatalf("child = %+v", child)
	}

	// The sub-agent works under the delegated token, inside the narrowed scope only.
	opened, errText := call(t, sub, "attempt_open", map[string]any{"task": "tests for auth", "capability_token": e.tok(child)})
	if errText != "" {
		t.Fatalf("sub-agent attempt_open: %s", errText)
	}
	for path, wantOK := range map[string]bool{"src/auth/login.go": true, "docs/readme.md": false, "src/secret/k": false} {
		_, errText = call(t, sub, "attempt_write", map[string]any{"attempt": opened["id"], "path": path, "content": "x", "capability_token": e.tok(child)})
		if wantOK && errText != "" {
			t.Errorf("write %s under the delegated scope: %s", path, errText)
		}
		if !wantOK && errText == "" {
			t.Errorf("write %s outside the delegated scope was accepted", path)
		}
	}
	// The parent's own token still reaches what the child's does not.
	if _, errText = call(t, e.parent, "intent_list", map[string]any{"capability_token": e.tok(e.root)}); errText != "" {
		t.Fatalf("parent token stopped working after delegating: %s", errText)
	}
}

func TestDelegationThroughMCPRefusesToWiden(t *testing.T) {
	e := newDelegationEnv(t, func(p *identity.IssueParams) {
		p.Operations = []string{"attempt_open", "capability_delegate"}
		p.SpendCeilingMicros = i64p(100)
	})
	_, subKey := e.subAgent("agent:x")
	base := func(extra map[string]any) map[string]any {
		args := map[string]any{"principal": "agent:x", "holder_key": pubB64(subKey)}
		for k, v := range extra {
			args[k] = v
		}
		return args
	}
	for name, extra := range map[string]map[string]any{
		"wider scope":     {"scope": map[string]any{"allow": []string{"**"}, "deny": []string{"src/secret/**"}, "mode": "enforce"}},
		"dropped deny":    {"scope": map[string]any{"allow": []string{"src/**"}, "mode": "enforce"}},
		"extra operation": {"operations": []string{"attempt_open", "attempt_write"}},
		"all operations":  {"operations": []string{"*"}},
		"larger ceiling":  {"spend_ceiling_micros": 101},
		"longer lifetime": {"ttl_seconds": 7200},
		"relaxed mode":    {"scope": map[string]any{"allow": []string{"src/**"}, "deny": []string{"src/secret/**"}, "mode": "warn"}},
	} {
		if _, errText := e.delegate(e.root, base(extra)); !strings.Contains(errText, "widen") {
			t.Errorf("%s: error = %q, want a widening refusal", name, errText)
		}
	}
	if _, errText := e.delegate(e.root, base(map[string]any{"operations": []string{"attempt_open"}, "spend_ceiling_micros": 40})); errText != "" {
		t.Fatalf("a genuine narrowing was refused: %s", errText)
	}
}

func i64p(v int64) *int64 { return &v }

func TestOnlyTheHolderMayDelegateAndOnlyWhenAllowed(t *testing.T) {
	e := newDelegationEnv(t, nil)
	_, subKey := e.subAgent("agent:x")

	// A daemon whose key is not the token's holder cannot delegate it.
	impostor, _ := e.subAgent(e.parent.Principal) // same principal name, different key
	args := map[string]any{"principal": "agent:x", "holder_key": pubB64(subKey), "capability_token": e.tok(e.root)}
	if _, errText := call(t, impostor, "capability_delegate", args); !strings.Contains(errText, "only the holder") {
		t.Fatalf("delegating without the holder key = %q", errText)
	}

	// A token that excludes capability_delegate cannot be delegated, and the
	// operation check stops the call before it reaches the handler.
	noDelegate := newDelegationEnv(t, func(p *identity.IssueParams) { p.Operations = []string{"attempt_open"} })
	_, errText := call(t, noDelegate.parent, "capability_delegate", map[string]any{"principal": "agent:x", "holder_key": pubB64(subKey), "capability_token": noDelegate.tok(noDelegate.root)})
	if !strings.Contains(errText, "does not permit this operation") {
		t.Fatalf("delegating without the capability_delegate operation = %q", errText)
	}

	// A token issued with no holder key has nothing to delegate from.
	keyless := newDelegationEnv(t, func(p *identity.IssueParams) { p.HolderKey = nil })
	_, errText = call(t, keyless.parent, "capability_delegate", map[string]any{"principal": "agent:x", "holder_key": pubB64(subKey), "capability_token": keyless.tok(keyless.root)})
	if !strings.Contains(errText, "holder key") {
		t.Fatalf("delegating a token with no holder key = %q", errText)
	}

	// Delegation is meaningless without enforcement: there is no authority to narrow.
	open := newTestServer(t)
	if _, errText = call(t, open, "capability_delegate", map[string]any{"principal": "agent:x"}); !strings.Contains(errText, "enforcement") {
		t.Fatalf("delegating with enforcement off = %q", errText)
	}
}

func TestOperationSetIsEnforcedBeforeAToolRuns(t *testing.T) {
	e := newDelegationEnv(t, func(p *identity.IssueParams) {
		p.Operations = []string{"attempt_open", "attempt_status", "intent_list"}
	})
	tok := e.tok(e.root)

	opened, errText := call(t, e.parent, "attempt_open", map[string]any{"task": "do a thing", "capability_token": tok})
	if errText != "" {
		t.Fatalf("a permitted operation: %s", errText)
	}
	if _, errText = call(t, e.parent, "attempt_status", map[string]any{"attempt": opened["id"], "capability_token": tok}); errText != "" {
		t.Fatalf("a permitted operation: %s", errText)
	}
	for _, tool := range []string{"attempt_write", "attempt_commit", "evidence_ingest", "intent_create"} {
		_, errText = call(t, e.parent, tool, map[string]any{"attempt": opened["id"], "path": "src/a.go", "content": "x", "report": "x", "capability_token": tok})
		if !strings.Contains(errText, "does not permit this operation") || !strings.Contains(errText, tool) {
			t.Errorf("%s with a token that does not list it: %q", tool, errText)
		}
	}
	// A forged token still gets the specific signature error, not an operation error.
	forged := e.root
	forged.Operations = nil
	if _, errText = call(t, e.parent, "attempt_write", map[string]any{"attempt": opened["id"], "path": "src/a.go", "content": "x", "capability_token": e.tok(forged)}); !strings.Contains(errText, "signature invalid") {
		t.Fatalf("a token with its operation list stripped = %q, want a signature error", errText)
	}
}

func TestSpendCeilingStopsACommitAndCountsAgainstTheDelegator(t *testing.T) {
	e := newDelegationEnv(t, func(p *identity.IssueParams) { p.SpendCeilingMicros = i64p(100) })
	sub, subKey := e.subAgent("agent:sub")
	child, errText := e.delegate(e.root, map[string]any{"principal": "agent:sub", "holder_key": pubB64(subKey), "spend_ceiling_micros": 70})
	if errText != "" {
		t.Fatal(errText)
	}

	commit := func(srv *Server, tok specv1.CapabilityToken, cost int, path string) string {
		opened, et := call(t, srv, "attempt_open", map[string]any{"task": "work " + path, "capability_token": e.tok(tok)})
		if et != "" {
			t.Fatalf("attempt_open: %s", et)
		}
		if _, et = call(t, srv, "attempt_write", map[string]any{"attempt": opened["id"], "path": path, "content": path, "capability_token": e.tok(tok)}); et != "" {
			t.Fatalf("attempt_write: %s", et)
		}
		_, et = call(t, srv, "attempt_commit", map[string]any{"attempt": opened["id"], "cost_micros": cost, "capability_token": e.tok(tok)})
		return et
	}

	// The parent spends 60 of its 100.
	if et := commit(e.parent, e.root, 60, "src/a.go"); et != "" {
		t.Fatalf("parent commit within its ceiling: %s", et)
	}
	// The sub-agent has its own 70, but only 40 of the parent's budget is left.
	if et := commit(sub, child, 50, "src/b.go"); !strings.Contains(et, "spend ceiling exceeded") {
		t.Fatalf("sub-agent commit past the delegator's remaining budget = %q", et)
	}
	if et := commit(sub, child, 40, "src/c.go"); et != "" {
		t.Fatalf("sub-agent commit within what is left: %s", et)
	}
	// The sub-agent's own ceiling (70) is now at 40; 31 more would exceed the parent's 100 first.
	if et := commit(sub, child, 1, "src/d.go"); !strings.Contains(et, "spend ceiling exceeded") {
		t.Fatalf("the parent's budget is exhausted but a commit was accepted: %q", et)
	}
	spent, _ := e.parent.Graph.Spent(t.Context(), e.root.ID)
	if spent != 100 {
		t.Fatalf("root token spent = %d, want 100", spent)
	}
}

func TestAuthorityChainShowsEveryWriteBackToTheHuman(t *testing.T) {
	e := newDelegationEnv(t, nil)
	sub, subKey := e.subAgent("agent:tests-1")
	child, errText := e.delegate(e.root, map[string]any{"principal": "agent:tests-1", "holder_key": pubB64(subKey)})
	if errText != "" {
		t.Fatal(errText)
	}

	opened, errText := call(t, sub, "attempt_open", map[string]any{"task": "write tests", "capability_token": e.tok(child)})
	if errText != "" {
		t.Fatal(errText)
	}
	attemptID := opened["id"].(string)
	if _, errText = call(t, sub, "attempt_write", map[string]any{"attempt": attemptID, "path": "src/a_test.go", "content": "package a", "capability_token": e.tok(child)}); errText != "" {
		t.Fatal(errText)
	}
	if _, errText = call(t, e.parent, "attempt_status", map[string]any{"attempt": attemptID, "capability_token": e.tok(e.root)}); errText != "" {
		t.Fatal(errText)
	}

	out, errText := call(t, e.parent, "authority_chain", map[string]any{"ref": attemptID, "capability_token": e.tok(e.root)})
	if errText != "" {
		t.Fatalf("authority_chain: %s", errText)
	}
	writes := out["writes"].([]any)
	if len(writes) != 2 { // open and write; status is a read and is not recorded
		t.Fatalf("recorded writes = %d, want 2: %v", len(writes), writes)
	}
	for _, w := range writes {
		entry := w.(map[string]any)
		chain := entry["chain"].([]any)
		if entry["actor"] != "agent:tests-1" || entry["origin"] != "human:lakin" || entry["verified"] != true || len(chain) != 2 {
			t.Fatalf("entry = %v", entry)
		}
		if chain[0].(map[string]any)["principal"] != "agent:tests-1" || chain[1].(map[string]any)["principal"] != e.parent.Principal {
			t.Fatalf("chain = %v, want the sub-agent then its delegator", chain)
		}
	}
	if writes[1].(map[string]any)["path"] != "src/a_test.go" || writes[1].(map[string]any)["op"] != "attempt_write" {
		t.Fatalf("second write = %v", writes[1])
	}

	// The delegation itself is a recorded write, made by the delegator.
	all, _ := call(t, e.parent, "authority_chain", map[string]any{"capability_token": e.tok(e.root)})
	foundDelegate := false
	for _, w := range all["writes"].([]any) {
		if w.(map[string]any)["op"] == "capability_delegate" && w.(map[string]any)["object"] == child.ID {
			foundDelegate = true
		}
	}
	if !foundDelegate {
		t.Fatalf("the delegation was not recorded: %v", all)
	}

	// A token bound to one intent may not read the audit trail.
	bound := issueToken(t, e.issuer, e.parent.Principal, opened["intent"].(string))
	if _, errText = call(t, e.parent, "authority_chain", map[string]any{"capability_token": tokenArg(t, bound)}); !strings.Contains(errText, "cannot create new intents") && !strings.Contains(errText, "repository-level") {
		t.Fatalf("a bound token reading the authority chain = %q", errText)
	}
	if none, _ := call(t, e.parent, "authority_chain", map[string]any{"ref": "att_" + strings.Repeat("q", 52), "capability_token": e.tok(e.root)}); len(none["writes"].([]any)) != 0 {
		t.Fatalf("an unknown ref should have no writes: %v", none)
	}
}

func TestRevokingTheParentStopsTheSubAgent(t *testing.T) {
	e := newDelegationEnv(t, nil)
	list := identity.NewMemoryRevocationList()
	e.parent.Revocation = list
	sub, subKey := e.subAgent("agent:sub")
	sub.Revocation = list
	child, errText := e.delegate(e.root, map[string]any{"principal": "agent:sub", "holder_key": pubB64(subKey)})
	if errText != "" {
		t.Fatal(errText)
	}
	if _, errText = call(t, sub, "intent_list", map[string]any{"capability_token": e.tok(child)}); errText != "" {
		t.Fatalf("before revocation: %s", errText)
	}
	list.Revoke(e.root.ID)
	if _, errText = call(t, sub, "intent_list", map[string]any{"capability_token": e.tok(child)}); !strings.Contains(errText, "revoked") {
		t.Fatalf("a delegated token whose parent was revoked = %q", errText)
	}
}

func TestSubAgentCannotUseATokenIssuedToSomeoneElse(t *testing.T) {
	e := newDelegationEnv(t, nil)
	sub, subKey := e.subAgent("agent:sub")
	child, errText := e.delegate(e.root, map[string]any{"principal": "agent:sub", "holder_key": pubB64(subKey)})
	if errText != "" {
		t.Fatal(errText)
	}
	// The parent daemon (agent:impl-3) presents the child's token: wrong principal.
	if _, errText = call(t, e.parent, "intent_list", map[string]any{"capability_token": e.tok(child)}); !strings.Contains(errText, "different principal") {
		t.Fatalf("presenting someone else's delegated token = %q", errText)
	}
	_ = sub
}

func TestWritesAreNotRecordedWithoutEnforcement(t *testing.T) {
	s := newTestServer(t)
	if _, errText := call(t, s, "attempt_open", map[string]any{"task": "no auth here"}); errText != "" {
		t.Fatal(errText)
	}
	records, err := s.Graph.ListAuthority(t.Context(), "")
	if err != nil || len(records) != 0 {
		t.Fatalf("authority records without a token = %d, %v", len(records), err)
	}
	_ = graph.EmptyWorld
}
