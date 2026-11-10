package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The scenarios of SRS §11.3, "required, not optional", driven through the real
// binaries. The threat model (§7.4) is a compromised or misbehaving agent that
// holds valid credentials, so each test plays that agent and checks what stops it.
//
// Rows whose defence belongs to a later milestone are listed and skipped with
// the milestone named, so the matrix stays visible rather than quietly shrinking.

func TestAdversarial_AgentWritesOutsideDeclaredScope(t *testing.T) {
	p := newProject(t)
	intent := p.declare("Only the auth package", "--files", "src/auth/**")
	a := p.startAgent()
	attempt := a.must("attempt_open", map[string]any{"intent": intent})["id"]

	for _, path := range []string{"docs/readme.md", "src/billing/charge.go", "go.mod"} {
		_, msg := a.call("attempt_write", map[string]any{"attempt": attempt, "path": path, "content": "x"})
		if !strings.Contains(msg, path) || !strings.Contains(msg, "outside the scope") {
			t.Errorf("write %s: %q, want a legible rejection naming the path", path, msg)
		}
	}
	// Traversal and absolute paths are not a way around the scope.
	for _, path := range []string{"../outside.go", "src/auth/../billing/x.go", "/etc/passwd", "src\\auth\\x.go"} {
		if _, msg := a.call("attempt_write", map[string]any{"attempt": attempt, "path": path, "content": "x"}); msg == "" {
			t.Errorf("write %q was accepted", path)
		}
	}
	status := a.must("attempt_status", map[string]any{"attempt": attempt})
	if files, _ := status["workspace_files"].([]any); len(files) != 0 {
		t.Errorf("rejected writes left files in the workspace: %v", files)
	}

	// warn mode accepts the write but never silently: it is recorded.
	warn := p.declare("Warn only", "--files", "src/auth/**", "--mode", "warn")
	b := a.must("attempt_open", map[string]any{"intent": warn})["id"]
	out := a.must("attempt_write", map[string]any{"attempt": b, "path": "docs/x.md", "content": "x"})
	if out["warning"] == nil {
		t.Errorf("a warn-mode write should carry a warning: %v", out)
	}
	if shown := p.mei("attempt", "show", b.(string)[:14]); !strings.Contains(shown, "1 violation(s)") || !strings.Contains(shown, "docs/x.md") {
		t.Errorf("the violation should be recorded on the attempt:\n%s", shown)
	}
}

func TestAdversarial_AgentSubmitsEvidenceForAWorldItAuthored(t *testing.T) {
	p := newProject(t)
	intent := p.declare("Work", "--files", "src/**")
	a := p.startAgent()
	attempt := a.must("attempt_open", map[string]any{"intent": intent})["id"].(string)
	a.must("attempt_write", map[string]any{"attempt": attempt, "path": "src/a.go", "content": "package a"})
	a.must("attempt_commit", map[string]any{"attempt": attempt})

	// The agent grades its own homework, and cannot pass it off as independent.
	own := a.must("evidence_ingest", map[string]any{"attempt": attempt, "report": junitPass})["evidence"].(map[string]any)
	if own["independent"] == true {
		t.Fatal("evidence the author produced was marked independent")
	}
	if _, msg := a.call("evidence_submit", map[string]any{
		"attempt": attempt, "producer": "human:anandk", "world": own["world"], "kind": "test-run", "outcome": "pass", "payload": map[string]any{"tests": 1},
	}); !strings.Contains(msg, "does not match the authenticated principal") {
		t.Errorf("an agent naming a human as the producer: %q", msg)
	}
	// And it cannot make an independent failure stop counting by "correcting" it.
	p.write("fail.xml", junitFail)
	out := p.mei("evidence", "submit", "--attempt", attempt, "--from", "fail.xml", "--producer", "agent:ci", "--key", filepath.Join(p.dir, ".meiosis", "agent.private.key"))
	if !strings.Contains(out, "test-run fail") {
		t.Fatalf("the independent failure was not recorded:\n%s", out)
	}
	var ciID string
	for _, e := range p.evidenceJSON(attempt) {
		if e["producer"] == "agent:ci" {
			ciID = e["id"].(string)
		}
	}
	if ciID == "" {
		t.Fatal("no agent:ci evidence found")
	}
	if _, msg := a.call("evidence_ingest", map[string]any{"attempt": attempt, "report": junitPass, "supersedes": ciID}); !strings.Contains(msg, "only the producer") {
		t.Errorf("the author superseding CI's failure: %q", msg)
	}
	// What M1 guarantees is that the facts are recorded truthfully: the merge
	// gate that refuses non-independent evidence is M2 (the policy engine).
	shown := p.mei("attempt", "show", attempt[:14])
	if !strings.Contains(shown, "NOT independent") || !strings.Contains(shown, "independent, fresh") {
		t.Errorf("both kinds of evidence should be shown for what they are:\n%s", shown)
	}
}

func TestAdversarial_SubAgentRequestsAWiderCapabilityThanItsParent(t *testing.T) {
	p := newProject(t, "--allow", "src/**", "--deny", "src/secret/**")
	a := p.startAgent()
	subKey := filepath.Join(t.TempDir(), "sub.key")

	// Through the CLI...
	token := filepath.Join(p.dir, ".agents", "meiosis-capability.json")
	agentKey := filepath.Join(p.dir, ".meiosis", "agent.private.key")
	for name, extra := range map[string][]string{
		"wider paths":     {"--allow", "**"},
		"dropped deny":    {"--allow", "src/**", "--mode", "warn"},
		"longer lifetime": {"--ttl", "9999h"},
	} {
		out, err := p.meiErr(append([]string{"intent", "delegate", "--token", token, "--key", agentKey, "--to", "agent:sub", "--generate-key", subKey}, extra...)...)
		if err == nil || !strings.Contains(out, "widen") {
			t.Errorf("CLI, %s: %v\n%s", name, err, out)
		}
	}
	if _, err := os.Stat(subKey); err == nil {
		t.Error("a refused delegation left a private key behind")
	}

	// ...and through the agent itself.
	for name, args := range map[string]map[string]any{
		"wider paths":    {"scope": map[string]any{"allow": []string{"**"}, "deny": []string{"src/secret/**"}, "mode": "enforce"}},
		"drops the deny": {"scope": map[string]any{"allow": []string{"src/**"}, "mode": "enforce"}},
	} {
		args["principal"] = "agent:sub"
		if _, msg := a.call("capability_delegate", args); !strings.Contains(msg, "widen") {
			t.Errorf("MCP, %s: %q", name, msg)
		}
	}
	child, msg := a.call("capability_delegate", map[string]any{"principal": "agent:sub", "scope": map[string]any{"allow": []string{"src/auth/**"}, "deny": []string{"src/secret/**"}, "mode": "enforce"}})
	if msg != "" || child["origin"] == "" {
		t.Fatalf("a genuine narrowing was refused: %s", msg)
	}
}

func TestAdversarial_EvidenceForASupersededWorld(t *testing.T) {
	p := newProject(t)
	intent := p.declare("Work", "--files", "src/**")
	a := p.startAgent()
	attempt := a.must("attempt_open", map[string]any{"intent": intent})["id"].(string)
	a.must("attempt_write", map[string]any{"attempt": attempt, "path": "src/a.go", "content": "v1"})
	first := a.must("attempt_commit", map[string]any{"attempt": attempt})["world"].(string)
	a.must("attempt_write", map[string]any{"attempt": attempt, "path": "src/a.go", "content": "v2"})
	second := a.must("attempt_commit", map[string]any{"attempt": attempt})["world"].(string)
	if first == second {
		t.Fatal("the world did not change")
	}

	// Evidence against the old world is accepted...
	p.write("pass.xml", junitPass)
	out := p.mei("evidence", "submit", "--attempt", attempt, "--from", "pass.xml", "--world", first)
	if !strings.Contains(out, "test-run pass") {
		t.Fatalf("evidence for an earlier world was refused:\n%s", out)
	}
	// ...but is marked stale and never counted.
	shown := p.mei("attempt", "show", attempt[:14])
	if !strings.Contains(shown, "STALE") || !strings.Contains(shown, "not counted") {
		t.Errorf("evidence for a superseded world must be shown as stale:\n%s", shown)
	}
	if status := p.mei("status"); !strings.Contains(status, "counted 0, stale 1") {
		t.Errorf("stale evidence must not count:\n%s", status)
	}
	// Evidence against the current world does count.
	p.mei("evidence", "submit", "--attempt", attempt, "--from", "pass.xml", "--world", second)
	if status := p.mei("status"); !strings.Contains(status, "counted 1, stale 1") {
		t.Errorf("fresh evidence should count:\n%s", status)
	}
}

func TestAdversarial_ForgedAndStolenCredentials(t *testing.T) {
	p := newProject(t)
	intent := p.declare("Work", "--files", "src/**")
	a := p.startAgent()

	// A token with its scope edited after signing.
	forged := p.agentToken()
	forged["scope"] = map[string]any{"allow": []string{"**"}, "mode": "enforce"}
	forged["issued_by"] = "human:mallory"
	if _, msg := a.call("attempt_open", map[string]any{"intent": intent, "capability_token": forged}); !strings.Contains(msg, "signature invalid") {
		t.Errorf("an edited token: %q", msg)
	}
	// A token stripped of its operation limits keeps no limits it was never given,
	// but one that had them cannot have them removed.
	limited := p.mei("intent", "authorize", "--principal", "agent:meiosis", "--intent", intent, "--issuer", "human:anandk",
		"--issuer-key", filepath.Join(p.dir, ".meiosis", "human.private.key"), "--allow", "**", "--operation", "attempt_status")
	var lt map[string]any
	if err := json.Unmarshal([]byte(limited), &lt); err != nil {
		t.Fatal(err)
	}
	if _, msg := a.call("attempt_open", map[string]any{"intent": intent, "capability_token": lt}); !strings.Contains(msg, "does not permit this operation") {
		t.Errorf("a token limited to attempt_status opening an attempt: %q", msg)
	}
	delete(lt, "operations")
	if _, msg := a.call("attempt_open", map[string]any{"intent": intent, "capability_token": lt}); !strings.Contains(msg, "signature invalid") {
		t.Errorf("a token with its operation list removed: %q", msg)
	}
	// No token at all.
	if _, msg := a.call("attempt_open", map[string]any{"intent": intent, "capability_token": nil}); msg == "" {
		t.Error("a call with a null token was accepted")
	}
	// A token issued to someone else.
	other := p.mei("intent", "authorize", "--principal", "agent:someone-else", "--intent", intent, "--issuer", "human:anandk",
		"--issuer-key", filepath.Join(p.dir, ".meiosis", "human.private.key"), "--allow", "**")
	var ot map[string]any
	_ = json.Unmarshal([]byte(other), &ot)
	if _, msg := a.call("attempt_open", map[string]any{"intent": intent, "capability_token": ot}); !strings.Contains(msg, "different principal") {
		t.Errorf("another principal's token: %q", msg)
	}

	// Revocation takes effect on the very next call, without restarting anything.
	a.must("attempt_open", map[string]any{"intent": intent})
	p.mei("intent", "revoke", "--token", ".agents/meiosis-capability.json")
	if _, msg := a.call("attempt_open", map[string]any{"intent": intent}); !strings.Contains(msg, "revoked") {
		t.Errorf("a revoked token: %q", msg)
	}
}

func TestAdversarial_ABackdatedTimestampIsNotAccepted(t *testing.T) {
	p := newProject(t)
	intent := p.declare("Work", "--files", "src/**")
	a := p.startAgent()
	attempt := a.must("attempt_open", map[string]any{"intent": intent})["id"].(string)
	a.must("attempt_write", map[string]any{"attempt": attempt, "path": "src/a.go", "content": "x"})
	world := a.must("attempt_commit", map[string]any{"attempt": attempt})["world"]

	// The submitter supplies a timestamp; the server has no field for it and
	// sets the time itself. (The audit log that makes ordering tamper-evident
	// is M3; until then there is simply nothing to backdate.)
	ev := a.must("evidence_submit", map[string]any{
		"attempt": attempt, "world": world, "kind": "test-run", "outcome": "pass", "payload": map[string]any{"tests": 1},
		"created_at": "2001-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
	})
	created, err := time.Parse(time.RFC3339, ev["created_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if age := time.Since(created); age < -time.Minute || age > time.Minute {
		t.Errorf("evidence created_at = %s: a client-supplied timestamp was honoured", created)
	}
	if ev["expires_at"] != nil && ev["expires_at"] != "0001-01-01T00:00:00Z" {
		t.Errorf("a client-supplied expiry was honoured: %v", ev["expires_at"])
	}
}

func TestAdversarial_ServerRunsFullyWithNoNetworkAccess(t *testing.T) {
	// The processes are started with no usable proxy and their sockets inspected
	// afterwards. A hermetic network namespace would be stronger and is left to
	// CI that has one; what this proves is that nothing in a full session opens
	// a socket to anything but this machine.
	p := newProject(t)
	intent := p.declare("Offline work", "--files", "src/**")
	a := p.startAgent()
	srv := p.serve()

	attempt := a.must("attempt_open", map[string]any{"intent": intent})["id"].(string)
	a.must("attempt_write", map[string]any{"attempt": attempt, "path": "src/a.go", "content": "x"})
	a.must("attempt_commit", map[string]any{"attempt": attempt})
	a.must("evidence_ingest", map[string]any{"attempt": attempt, "report": junitPass})
	p.mei("remote", "add", "meiosis", "--url", srv.url+"/shop.git")
	p.git("add", "-A")
	p.git("commit", "-q", "-m", "all")
	if out, err := p.run("git", "push", "meiosis", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}

	assertLoopbackOnly(t, "meiosisd", a.pid())
	assertLoopbackOnly(t, "mei serve", srv.cmd.Process.Pid)
}

func (p *project) evidenceJSON(attempt string) []map[string]any {
	p.t.Helper()
	var records []map[string]any
	if err := json.Unmarshal([]byte(p.mei("evidence", "list", "--attempt", attempt, "--format", "json")), &records); err != nil {
		p.t.Fatal(err)
	}
	return records
}

// ---- rows that belong to later milestones ------------------------------------

func TestAdversarial_PolicyFileThatFailsToCompile(t *testing.T) {
	t.Skip("M2: needs the Rego policy engine (FR-5.3, PR-2). Expected: all merges blocked, not defaulted open.")
}

func TestAdversarial_TwoAttemptsCleanTextMergeIncompatibleSignature(t *testing.T) {
	t.Skip("M3: needs semantic conflict detection (FR-6.4). Expected: a semantic conflict raised naming the symbol.")
}

func TestAdversarial_MergeGateRefusesNonIndependentEvidence(t *testing.T) {
	t.Skip("M2: needs the policy gate (FR-4.5, FR-5.4). M1 records independence truthfully; see TestAdversarial_AgentSubmitsEvidenceForAWorldItAuthored.")
}

func TestAdversarial_AuditLogOrderingRejectsBackdatedEvidence(t *testing.T) {
	t.Skip("M3: needs the Merkle audit log (FR-8.3). M1 never accepts a client-supplied timestamp; see TestAdversarial_ABackdatedTimestampIsNotAccepted.")
}
