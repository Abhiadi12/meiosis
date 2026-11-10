package acceptance

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// firstValueBudget is NFR-5.4: time-to-first-value under five minutes.
const firstValueBudget = 5 * time.Minute

// TestM1ExitCriterion is the milestone's exit criterion as a script (SRS §10):
//
//	A solo developer with one agent gets a rejected out-of-scope write and a
//	provenance record, in under 5 minutes from download, with no config.
//
// "From download" is measured from the moment the binaries exist; the time to
// download them is the network's, not the product's, and the build time is
// logged beside it. Everything runs through the real binaries.
func TestM1ExitCriterion(t *testing.T) {
	started := time.Now()

	// 1. One command to set up, no flags, no config files to write.
	p := newProject(t)

	// 2. The human says what the agent may touch.
	intent := p.declare("Fix the login redirect", "--files", "src/auth/**", "--deny", "src/auth/secrets/**")

	// 3. The agent (an MCP client talking to meiosisd, exactly as an IDE would
	//    start it) opens an attempt under that intent.
	a := p.startAgent()
	opened := a.must("attempt_open", map[string]any{"intent": intent})
	attempt := opened["id"].(string)

	// 4. An out-of-scope write is rejected, at write time, with a message a
	//    person can act on.
	_, rejected := a.call("attempt_write", map[string]any{"attempt": attempt, "path": "docs/notes.md", "content": "stray"})
	for _, want := range []string{"docs/notes.md", "outside the scope of intent " + intent, "no allow rule", "mode: enforce"} {
		if !strings.Contains(rejected, want) {
			t.Errorf("the rejection should say %q, got:\n%s", want, rejected)
		}
	}
	if _, denied := a.call("attempt_write", map[string]any{"attempt": attempt, "path": "src/auth/secrets/key.pem", "content": "x"}); !strings.Contains(denied, `deny rule "src/auth/secrets/**"`) {
		t.Errorf("a denied path should name the deny rule, got: %s", denied)
	}

	// 5. The in-scope work is accepted and committed with provenance.
	a.must("attempt_write", map[string]any{"attempt": attempt, "path": "src/auth/login.go", "content": "package auth\n\nfunc Redirect() string { return \"/next\" }\n"})
	committed := a.must("attempt_commit", map[string]any{
		"attempt": attempt, "model": "claude-opus-5", "model_ver": "2026-01", "tools": []string{"editor", "go test"},
		"prompt": "fix the login redirect so it honours ?next=", "tokens_in": 1200, "tokens_out": 340, "cost_micros": 4200,
	})
	world := committed["world"].(string)

	// 6. Evidence: the agent's own test run, and an independent one from the human.
	a.must("evidence_ingest", map[string]any{"attempt": attempt, "report": junitPass})
	p.write("junit.xml", junitPass)
	p.mei("evidence", "submit", "--attempt", attempt, "--from", "junit.xml")

	// 7. The provenance record, printed.
	shown := p.mei("attempt", "show", attempt[:14])
	for _, want := range []string{
		"agent:meiosis", "no violations", "claude-opus-5", "2026-01", "editor, go test", "tokens in/out 1200/340", "cost 4200 micros",
		"src/auth/login.go", "NOT independent", "independent, fresh", world,
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("mei attempt show is missing %q:\n%s", want, shown)
		}
	}
	if strings.Contains(shown, "fix the login redirect so it honours") {
		t.Error("the prompt text was stored or shown; only its digest may be (NFR-4.2)")
	}
	if strings.Contains(shown, "docs/notes.md") || strings.Contains(shown, "key.pem") {
		t.Errorf("a rejected path leaked into the attempt:\n%s", shown)
	}
	status := p.mei("status")
	if !strings.Contains(status, "evidence   2 (counted 2, stale 0, superseded 0, not independent 1)") {
		t.Errorf("mei status:\n%s", status)
	}

	elapsed := time.Since(started)
	t.Logf("exit criterion reached in %s (budget %s); building the binaries took a further %s", elapsed.Round(10*time.Millisecond), firstValueBudget, buildTime.Round(time.Second))
	if elapsed > firstValueBudget {
		t.Fatalf("time to first value was %s, over the %s budget (NFR-5.4)", elapsed, firstValueBudget)
	}

	// 8. The same project, over Git: serve, add the remote, push.
	srv := p.serve()
	p.mei("remote", "add", "meiosis", "--url", srv.url+"/shop.git")
	// The project's first push names no intent, which is how solo adoption
	// starts: it is accepted under an implicit intent in warn mode.
	p.write("src/auth/login.go", "package auth\n\nfunc Redirect() string { return \"/home\" }\n")
	p.git("add", "-A")
	p.git("commit", "-q", "-m", "Initial import")
	if out, err := p.run("git", "push", "meiosis", "main"); err != nil || !strings.Contains(out, "implicit intent") {
		t.Fatalf("the first push (no intent): %v\n%s", err, out)
	}
	// The fix is pushed under the declared intent, whose scope now binds it.
	p.write("src/auth/login.go", "package auth\n\nfunc Redirect() string { return \"/next\" }\n")
	p.git("commit", "-q", "-am", "Fix the login redirect")
	pushed, err := p.run("git", "push", "-o", "intent="+intent, "meiosis", "main")
	if err != nil {
		t.Fatalf("git push through meiosis: %v\n%s", err, pushed)
	}
	if !strings.Contains(pushed, "accepted as human:") || !strings.Contains(pushed, "under intent "+intent) || !strings.Contains(pushed, "-> world") {
		t.Errorf("push output:\n%s", pushed)
	}
	// A stray change outside the intent's scope is refused, and the ref stays put.
	p.write("docs/stray.md", "stray")
	p.git("add", "-A")
	p.git("commit", "-q", "-m", "Stray doc")
	if out, err := p.run("git", "push", "-o", "intent="+intent, "meiosis", "main"); err == nil || !strings.Contains(out, "docs/stray.md") || !strings.Contains(out, "REJECTED") {
		t.Fatalf("an out-of-scope push should be rejected naming the path: %v\n%s", err, out)
	}

	refs := p.mei("refs", "--format", "json")
	var rows []struct {
		Update struct {
			World    string `json:"world"`
			Intent   string `json:"intent"`
			Implicit bool   `json:"implicit_intent"`
		} `json:"update"`
		Verified bool `json:"signature_verified"`
	}
	if err := json.Unmarshal([]byte(refs), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("mei refs: %v\n%s", err, refs)
	}
	if !rows[0].Update.Implicit || rows[1].Update.Implicit || rows[1].Update.Intent != intent {
		t.Errorf("ref updates = %+v, want an implicit one then one under the named intent", rows)
	}
	for _, r := range rows {
		if !r.Verified || len(r.Update.World) != 64 {
			t.Errorf("ref update = %+v, want a verified signed world hash", r)
		}
	}
	if rows[0].Update.World == rows[1].Update.World {
		t.Error("the fix did not change the world hash")
	}

	// 9. Nothing in all of that reached outside this machine (NFR-4.5).
	assertLoopbackOnly(t, "meiosisd", a.pid())
	if n := assertLoopbackOnly(t, "mei serve", srv.cmd.Process.Pid); n == 0 {
		t.Log("mei serve showed no listening socket to inspect")
	}
}

// NFR-5.2: first run is `mei serve` and nothing else. In a fresh git repository
// with no `mei init`, serving sets the repository up and works.
func TestServeAloneIsEnoughOnAFirstRun(t *testing.T) {
	p := &project{t: t, dir: filepath.Join(t.TempDir(), "fresh"), home: t.TempDir()}
	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p.git("init", "-q", "-b", "main")
	if _, err := os.Stat(filepath.Join(p.dir, ".meiosis")); err == nil {
		t.Fatal("the fixture should not be initialised")
	}

	srv := p.serve()
	for _, want := range []string{".meiosis/human.private.key", ".meiosis/config.yaml", ".agents/meiosis-capability.json"} {
		if _, err := os.Stat(filepath.Join(p.dir, filepath.FromSlash(want))); err != nil {
			t.Errorf("serve did not create %s: %v", want, err)
		}
	}
	if cfg := string(p.read(".meiosis/config.yaml")); !strings.Contains(cfg, "strict: true") {
		t.Errorf("first-run setup should be strict:\n%s", cfg)
	}

	// And it is a working, authenticated server: push a commit through it.
	p.mei("remote", "add", "meiosis", "--url", srv.url+"/fresh.git")
	p.write("hello.txt", "hi\n")
	p.git("add", "-A")
	p.git("commit", "-q", "-m", "first")
	if out, err := p.run("git", "push", "meiosis", "main"); err != nil || !strings.Contains(out, "-> world") {
		t.Fatalf("push to a server that set itself up: %v\n%s", err, out)
	}
	resp, err := http.Get(srv.url + "/fresh.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated request to the self-configured server should be refused, got %d", resp.StatusCode)
	}

	// --no-init refuses instead.
	q := &project{t: t, dir: filepath.Join(t.TempDir(), "other"), home: t.TempDir()}
	_ = os.MkdirAll(q.dir, 0o755)
	q.git("init", "-q", "-b", "main")
	if out, err := q.meiErr("serve", "--no-init"); err == nil || !strings.Contains(out, "mei init") {
		t.Fatalf("--no-init = %v\n%s", err, out)
	}
}
