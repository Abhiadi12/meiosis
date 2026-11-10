package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func declareJSON(t *testing.T, root string, args ...string) map[string]any {
	t.Helper()
	full := append([]string{"intent", "declare"}, args...)
	full = append(full, "--repo", root, "--created-by", "human:lakin", "--format", "json")
	var out map[string]any
	if err := json.Unmarshal([]byte(execute(t, full...)), &out); err != nil {
		t.Fatalf("declare output is not JSON: %v", err)
	}
	return out
}

func writeRepoFile(t *testing.T, root, name, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIntentNewIsAnAliasAndDeclareAcceptsLinksAndPins(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	writeRepoFile(t, root, "docs/adr-1.md", "we use sqlite")

	parent := declareJSON(t, root, "Parent")
	child := declareJSON(t, root, "Child", "--parent", parent["id"].(string), "--depends-on", parent["id"].(string),
		"--pin", "docs/adr-1.md", "--pin-kind", "adr", "--non-goal", "no refactor")
	pins, _ := child["context_pins"].([]any)
	if len(pins) != 1 || pins[0].(map[string]any)["kind"] != "adr" || pins[0].(map[string]any)["ref"] != "docs/adr-1.md" {
		t.Fatalf("context_pins = %v", child["context_pins"])
	}

	out := execute(t, "intent", "new", "Via alias", "--repo", root, "--created-by", "human:lakin")
	if !strings.Contains(out, "declared and signed") {
		t.Fatalf("alias output = %q", out)
	}

	cmd := New(nil)
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"intent", "declare", "Bad pin", "--repo", root, "--pin", "../escape.md"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a pin outside the repository was accepted")
	}
}

func TestIntentListAndShowReverifyPins(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	writeRepoFile(t, root, "docs/spec.md", "v1")
	intent := declareJSON(t, root, "Use the spec", "--pin", "docs/spec.md", "--files", "src/**")
	id := intent["id"].(string)

	list := execute(t, "intent", "list", "--repo", root)
	if !strings.Contains(list, "Use the spec") || !strings.Contains(list, "open") {
		t.Fatalf("list = %q", list)
	}

	show := execute(t, "intent", "show", id[:12], "--repo", root)
	for _, want := range []string{"Use the spec", "allow src/**", "docs/spec.md [spec]: match"} {
		if !strings.Contains(show, want) {
			t.Errorf("show output missing %q:\n%s", want, show)
		}
	}

	writeRepoFile(t, root, "docs/spec.md", "v2 - edited after it was pinned")
	show = execute(t, "intent", "show", id, "--repo", root)
	if !strings.Contains(show, "CHANGED since it was pinned") {
		t.Fatalf("a changed pinned document must be reported:\n%s", show)
	}
	if err := os.Remove(filepath.Join(root, "docs", "spec.md")); err != nil {
		t.Fatal(err)
	}
	if show = execute(t, "intent", "show", id, "--repo", root); !strings.Contains(show, "MISSING") {
		t.Fatalf("a deleted pinned document must be reported:\n%s", show)
	}
}

func TestIntentSupersedeInheritsUnspecifiedFields(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	old := declareJSON(t, root, "Old title", "--goal", "the goal", "--files", "src/**", "--deny", "src/secret/**", "--acceptance", "it works")

	out := execute(t, "intent", "supersede", old["id"].(string)[:12], "New title", "--repo", root, "--created-by", "human:lakin", "--format", "json")
	var successor map[string]any
	if err := json.Unmarshal([]byte(out), &successor); err != nil {
		t.Fatal(err)
	}
	if successor["title"] != "New title" || successor["goal"] != "the goal" {
		t.Fatalf("successor = %v, want a new title and the inherited goal", successor)
	}
	scope := successor["scope"].(map[string]any)
	if scope["allow"].([]any)[0] != "src/**" || scope["deny"].([]any)[0] != "src/secret/**" {
		t.Fatalf("scope not inherited: %v", scope)
	}

	list := execute(t, "intent", "list", "--repo", root)
	if strings.Contains(list, "Old title") {
		t.Fatalf("superseded intent shown by default:\n%s", list)
	}
	if all := execute(t, "intent", "list", "--all", "--repo", root); !strings.Contains(all, "Old title") || !strings.Contains(all, "(superseded)") {
		t.Fatalf("list --all = %q", all)
	}

	// Overriding a field changes only that field.
	third := execute(t, "intent", "supersede", successor["id"].(string), "Third", "--repo", root, "--created-by", "human:lakin", "--files", "lib/**", "--format", "json")
	var thirdIntent map[string]any
	_ = json.Unmarshal([]byte(third), &thirdIntent)
	thirdScope := thirdIntent["scope"].(map[string]any)
	if thirdScope["allow"].([]any)[0] != "lib/**" || thirdScope["deny"].([]any)[0] != "src/secret/**" {
		t.Fatalf("override scope = %v, want allow replaced and deny inherited", thirdScope)
	}

	cmd := New(nil)
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"intent", "supersede", old["id"].(string), "Again", "--repo", root})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "already superseded") {
		t.Fatalf("superseding twice = %v, want already superseded", err)
	}
}

func TestIntentPinSupersedesWithTheDigest(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	writeRepoFile(t, root, "docs/design.md", "design v1")
	old := declareJSON(t, root, "Build it", "--files", "src/**")

	out := execute(t, "intent", "pin", old["id"].(string), "docs/design.md", "--kind", "design", "--repo", root, "--created-by", "human:lakin", "--format", "json")
	var pinned map[string]any
	if err := json.Unmarshal([]byte(out), &pinned); err != nil {
		t.Fatal(err)
	}
	pins := pinned["context_pins"].([]any)
	if len(pins) != 1 || pins[0].(map[string]any)["kind"] != "design" {
		t.Fatalf("pins = %v", pins)
	}
	if pinned["id"] == old["id"] {
		t.Fatal("pinning must produce a successor, not mutate the intent")
	}
	if show := execute(t, "intent", "show", pinned["id"].(string), "--repo", root); !strings.Contains(show, "docs/design.md [design]: match") {
		t.Fatalf("show = %s", show)
	}

	// Pinning the same file again replaces its digest rather than duplicating the pin.
	writeRepoFile(t, root, "docs/design.md", "design v2")
	out = execute(t, "intent", "pin", pinned["id"].(string), "docs/design.md", "--kind", "design", "--repo", root, "--created-by", "human:lakin", "--format", "json")
	var repinned map[string]any
	_ = json.Unmarshal([]byte(out), &repinned)
	if n := len(repinned["context_pins"].([]any)); n != 1 {
		t.Fatalf("re-pin left %d pins, want 1", n)
	}
}

func TestIntentShowAndListWithoutStoreGuideTheUser(t *testing.T) {
	for _, args := range [][]string{{"intent", "list"}, {"intent", "show", "int_x"}} {
		cmd := New(nil)
		cmd.SetOut(&strings.Builder{})
		cmd.SetErr(&strings.Builder{})
		cmd.SetArgs(append(args, "--repo", t.TempDir()))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "mei init") {
			t.Fatalf("%v error = %v, want guidance to run mei init", args, err)
		}
	}
}
