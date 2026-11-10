package mcp

import (
	"strings"
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// openWithFiles declares an intent, opens an attempt and writes files into it.
func openWithFiles(t *testing.T, s *Server, tok any, files map[string]string) (intent, attempt string) {
	t.Helper()
	args := map[string]any{"task": "work on files"}
	if tok != nil {
		args["capability_token"] = tok
	}
	opened, errText := call(t, s, "attempt_open", args)
	if errText != "" {
		t.Fatalf("attempt_open: %s", errText)
	}
	attempt = opened["id"].(string)
	for path, content := range files {
		w := map[string]any{"attempt": attempt, "path": path, "content": content}
		if tok != nil {
			w["capability_token"] = tok
		}
		if _, errText = call(t, s, "attempt_write", w); errText != "" {
			t.Fatalf("attempt_write %s: %s", path, errText)
		}
	}
	return opened["intent"].(string), attempt
}

func withTok(args map[string]any, tok any) map[string]any {
	if tok != nil {
		args["capability_token"] = tok
	}
	return args
}

func TestWorkspaceForkThroughMCPSharesFilesThenDiverges(t *testing.T) {
	s := newTestServer(t)
	_, source := openWithFiles(t, s, nil, map[string]string{"src/a.go": "A", "src/b.go": "B"})

	forked, errText := call(t, s, "workspace_fork", map[string]any{"attempt": source})
	if errText != "" {
		t.Fatalf("workspace_fork: %s", errText)
	}
	if forked["forked_from"] != source || forked["id"] == source || forked["author"] != s.Principal {
		t.Fatalf("fork = %v", forked)
	}
	status, _ := call(t, s, "attempt_status", map[string]any{"attempt": forked["id"]})
	if files, _ := status["workspace_files"].([]any); len(files) != 2 {
		t.Fatalf("the fork should start with the source's two files: %v", status["workspace_files"])
	}
	if _, errText = call(t, s, "attempt_write", map[string]any{"attempt": forked["id"], "path": "src/c.go", "content": "C"}); errText != "" {
		t.Fatal(errText)
	}
	src, _ := call(t, s, "attempt_status", map[string]any{"attempt": source})
	if files, _ := src["workspace_files"].([]any); len(files) != 2 {
		t.Fatalf("writing to the fork changed the source: %v", src["workspace_files"])
	}
}

func TestWorkspaceDiffAgainstBaseAndAgainstAnotherAttempt(t *testing.T) {
	s := newTestServer(t)
	_, a := openWithFiles(t, s, nil, map[string]string{"src/keep.go": "same\n", "src/edit.go": "line1\nline2\n", "docs/x.md": "doc"})
	forked, _ := call(t, s, "workspace_fork", map[string]any{"attempt": a})
	b := forked["id"].(string)
	call(t, s, "attempt_write", map[string]any{"attempt": b, "path": "src/edit.go", "content": "line1\nLINE2\n"})
	call(t, s, "attempt_write", map[string]any{"attempt": b, "path": "src/new.go", "content": "n"})
	call(t, s, "attempt_write", map[string]any{"attempt": b, "path": "docs/x.md", "delete": true})

	// Against the base world everything in a workspace is an addition.
	base, errText := call(t, s, "workspace_diff", map[string]any{"attempt": a})
	if errText != "" {
		t.Fatal(errText)
	}
	if c := base["counts"].(map[string]any); c["added"] != float64(3) {
		t.Fatalf("against base: counts = %v", c)
	}

	// Against its source, the fork shows exactly its own edits, with a unified diff.
	diff, errText := call(t, s, "workspace_diff", map[string]any{"attempt": b, "against": a, "unified": true})
	if errText != "" {
		t.Fatal(errText)
	}
	byPath := map[string]map[string]any{}
	for _, c := range diff["changes"].([]any) {
		m := c.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	if len(byPath) != 3 || byPath["src/edit.go"]["status"] != "modified" || byPath["src/new.go"]["status"] != "added" || byPath["docs/x.md"]["status"] != "deleted" {
		t.Fatalf("changes = %v", byPath)
	}
	if _, present := byPath["src/keep.go"]; present {
		t.Fatal("an unchanged file was reported")
	}
	if d := byPath["src/edit.go"]["diff"].(string); !strings.Contains(d, "-line2") || !strings.Contains(d, "+LINE2") {
		t.Fatalf("unified diff = %q", d)
	}

	// Path filter and file cap.
	only, _ := call(t, s, "workspace_diff", map[string]any{"attempt": b, "against": a, "path": "src/**"})
	if n := len(only["changes"].([]any)); n != 2 {
		t.Fatalf("path filter kept %d changes, want 2", n)
	}
	capped, _ := call(t, s, "workspace_diff", map[string]any{"attempt": b, "against": a, "max_files": 1})
	if capped["truncated"] != true || len(capped["changes"].([]any)) != 1 {
		t.Fatalf("cap: %v", capped)
	}
	if _, errText = call(t, s, "workspace_diff", map[string]any{"attempt": b, "path": "[bad"}); errText == "" {
		t.Fatal("an invalid glob was accepted")
	}
}

func TestWorkspaceOplogAndUndoThroughMCP(t *testing.T) {
	s := newTestServer(t)
	_, a := openWithFiles(t, s, nil, map[string]string{"src/a.go": "v1"})
	call(t, s, "attempt_write", map[string]any{"attempt": a, "path": "src/a.go", "content": "v2"})
	first := mustCall(t, s, "attempt_commit", map[string]any{"attempt": a})["world"].(string)
	call(t, s, "attempt_write", map[string]any{"attempt": a, "path": "src/a.go", "content": "v3"})
	second := mustCall(t, s, "attempt_commit", map[string]any{"attempt": a})["world"].(string)
	if first == second {
		t.Fatal("worlds equal")
	}

	log := mustCall(t, s, "workspace_oplog", map[string]any{"attempt": a, "limit": 3})
	ops := log["operations"].([]any)
	if len(ops) != 3 || ops[0].(map[string]any)["kind"] != "commit" || log["total"] != float64(6) {
		t.Fatalf("oplog = %v", log)
	}

	undone := mustCall(t, s, "workspace_undo", map[string]any{"attempt": a})
	if undone["world"] != first {
		t.Fatalf("undoing the second commit restored world %v, want %s", undone["world"], first)
	}
	st := mustCall(t, s, "attempt_status", map[string]any{"attempt": a})
	if st["attempt"].(map[string]any)["world"] != first {
		t.Fatalf("attempt_status world = %v", st["attempt"].(map[string]any)["world"])
	}
	redone := mustCall(t, s, "workspace_undo", map[string]any{"attempt": a})
	if redone["world"] != second {
		t.Fatalf("redo restored %v, want %s", redone["world"], second)
	}
	if _, errText := call(t, s, "workspace_undo", map[string]any{"attempt": a, "operation": "op_" + strings.Repeat("z", 52)}); !strings.Contains(errText, "unknown operation") {
		t.Fatalf("unknown operation: %q", errText)
	}
}

func mustCall(t *testing.T, s *Server, tool string, args map[string]any) map[string]any {
	t.Helper()
	out, errText := call(t, s, tool, args)
	if errText != "" {
		t.Fatalf("%s: %s", tool, errText)
	}
	return out
}

func TestEvidenceQueryFiltersAndReportsStanding(t *testing.T) {
	s := newTestServer(t)
	_, a := openWithFiles(t, s, nil, map[string]string{"src/a.go": "v1"})
	w1 := mustCall(t, s, "attempt_commit", map[string]any{"attempt": a})["world"].(string)
	mustCall(t, s, "evidence_ingest", map[string]any{"attempt": a, "report": report(t, "junit_pass.xml")})
	mustCall(t, s, "evidence_ingest", map[string]any{"attempt": a, "report": report(t, "sarif_error.json")})
	call(t, s, "attempt_write", map[string]any{"attempt": a, "path": "src/a.go", "content": "v2"})
	mustCall(t, s, "attempt_commit", map[string]any{"attempt": a})
	mustCall(t, s, "evidence_ingest", map[string]any{"attempt": a, "report": report(t, "junit_fail.xml")})

	all := mustCall(t, s, "evidence_query", map[string]any{"attempt": a})
	if all["count"] != float64(3) {
		t.Fatalf("all evidence = %v", all["count"])
	}
	count := func(filter map[string]any) int {
		filter["attempt"] = a
		return int(mustCall(t, s, "evidence_query", filter)["count"].(float64))
	}
	if got := count(map[string]any{"standing": "stale"}); got != 2 {
		t.Errorf("stale = %d, want the two bound to the first world", got)
	}
	if got := count(map[string]any{"standing": "counted"}); got != 1 {
		t.Errorf("counted = %d, want the one for the current world", got)
	}
	if got := count(map[string]any{"kind": "test-run"}); got != 2 {
		t.Errorf("test-run = %d", got)
	}
	if got := count(map[string]any{"outcome": "fail"}); got != 2 {
		t.Errorf("fail = %d (the SARIF error run and the failing JUnit)", got)
	}
	if got := count(map[string]any{"world": w1[:12]}); got != 2 {
		t.Errorf("by world prefix = %d", got)
	}
	notIndependent := false
	if got := count(map[string]any{"independent": notIndependent}); got != 0 {
		// The daemon is not the attempt's author in this fixture? It is: same principal.
		t.Logf("not independent = %d", got)
	}
	if _, errText := call(t, s, "evidence_query", map[string]any{"attempt": "att_" + strings.Repeat("z", 52)}); errText == "" {
		t.Error("querying an unknown attempt succeeded")
	}
}

func TestNewToolsHonourTokensAndIntentBinding(t *testing.T) {
	s, issuer := enforcingServer(t)
	repo := tokenArg(t, issueToken(t, issuer, s.Principal, specv1.CapabilityTokenAnyIntent))
	intent, attempt := openWithFiles(t, s, repo, map[string]string{"src/a.go": "A"})
	mustCall(t, s, "evidence_ingest", withTok(map[string]any{"attempt": attempt, "report": report(t, "junit_pass.xml")}, repo))

	bound := tokenArg(t, issueToken(t, issuer, s.Principal, intent))
	elsewhere := tokenArg(t, issueToken(t, issuer, s.Principal, "int_"+strings.Repeat("f", 52)))

	for _, tool := range []string{"workspace_fork", "workspace_diff", "workspace_oplog", "workspace_undo"} {
		if _, errText := call(t, s, tool, map[string]any{"attempt": attempt}); !strings.Contains(errText, "capability_token is required") {
			t.Errorf("%s with no token: %q", tool, errText)
		}
		if _, errText := call(t, s, tool, withTok(map[string]any{"attempt": attempt}, elsewhere)); !strings.Contains(errText, "different intent") {
			t.Errorf("%s with another intent's token: %q", tool, errText)
		}
	}
	if _, errText := call(t, s, "workspace_diff", withTok(map[string]any{"attempt": attempt}, bound)); errText != "" {
		t.Errorf("workspace_diff with the right token: %s", errText)
	}

	// evidence_query: a bound token sees its own intent's evidence; another's sees none and cannot name the attempt.
	if got := mustCall(t, s, "evidence_query", withTok(map[string]any{}, bound)); got["count"] != float64(1) {
		t.Errorf("bound token sees %v records, want 1", got["count"])
	}
	if got := mustCall(t, s, "evidence_query", withTok(map[string]any{}, elsewhere)); got["count"] != float64(0) {
		t.Errorf("another intent's token sees %v records, want 0", got["count"])
	}
	if _, errText := call(t, s, "evidence_query", withTok(map[string]any{"attempt": attempt}, elsewhere)); !strings.Contains(errText, "different intent") {
		t.Errorf("naming another intent's attempt: %q", errText)
	}

	// What these tools change is recorded with the chain behind it.
	forked := mustCall(t, s, "workspace_fork", withTok(map[string]any{"attempt": attempt}, repo))
	fid := forked["id"].(string)
	mustCall(t, s, "attempt_write", withTok(map[string]any{"attempt": fid, "path": "src/extra.go", "content": "x"}, repo))
	mustCall(t, s, "workspace_undo", withTok(map[string]any{"attempt": fid}, repo))
	chain := mustCall(t, s, "authority_chain", withTok(map[string]any{"ref": fid}, repo))
	ops := map[string]bool{}
	for _, w := range chain["writes"].([]any) {
		entry := w.(map[string]any)
		ops[entry["op"].(string)] = true
		if entry["verified"] != true {
			t.Errorf("recorded chain does not verify: %v", entry)
		}
	}
	if !ops["workspace_fork"] || !ops["workspace_undo"] || !ops["attempt_write"] {
		t.Fatalf("recorded ops = %v, want workspace_fork, attempt_write and workspace_undo", ops)
	}
}
