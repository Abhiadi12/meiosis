// Package architecture enforces the dependency rules in docs/architecture.md.
// It is a test only: a package that imports something it must not fails here,
// so the layering cannot erode one convenient import at a time.
package architecture

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/mindfire-test/meiosis/"

// forbidden lists, per package (relative to the module), the packages it must
// never import, directly. A trailing /... matches a whole subtree.
var forbidden = map[string][]string{
	// The public format and its primitives know nothing of the implementation.
	"pkg/spec/v1":        {"internal/...", "pkg/crypto", "pkg/storage/...", "pkg/worlds", "pkg/gitserver"},
	"pkg/crypto":         {"internal/...", "pkg/storage/...", "pkg/worlds", "pkg/gitserver"},
	"pkg/worlds":         {"internal/...", "pkg/storage/...", "pkg/crypto"},
	"pkg/storage":        {"internal/...", "pkg/spec/..."},
	"pkg/storage/sqlite": {"internal/..."},
	"pkg/gitserver":      {"internal/...", "pkg/spec/..."},

	// Leaves: pure helpers with no knowledge of the object graph.
	"internal/secrets":    {"internal/...", "pkg/..."},
	"internal/textdiff":   {"internal/...", "pkg/..."},
	"internal/metrics":    {"internal/...", "pkg/..."},
	"internal/jsonschema": {"internal/...", "pkg/..."},
	"internal/scope":      {"internal/...", "pkg/crypto", "pkg/storage/...", "pkg/worlds"},

	// Domain core: identity and the graph never reach up into transports or UI.
	"internal/identity": {"internal/graph", "internal/mcp", "internal/server", "internal/cli", "internal/pushhook", "internal/evidence", "internal/gitops"},
	"internal/graph":    {"internal/mcp", "internal/server", "internal/cli", "internal/pushhook", "internal/evidence", "internal/gitops"},
	"internal/evidence": {"internal/mcp", "internal/server", "internal/cli", "internal/pushhook"},
	"internal/gitops":   {"internal/graph", "internal/identity", "internal/mcp", "internal/server", "internal/cli"},

	// Transports sit above the core and beside each other, never above the CLI.
	"internal/mcp":      {"internal/server", "internal/cli", "internal/pushhook"},
	"internal/pushhook": {"internal/mcp", "internal/server", "internal/cli"},
	"internal/server":   {"internal/cli"},

	// The stdio daemon is a transport of its own: beside the server, below main.
	"internal/daemon":     {"internal/cli", "internal/server", "internal/pushhook"},
	"internal/repoconfig": {"internal/...", "pkg/..."},

	// Entry points are thin: they call one internal package and nothing else.
	"cmd/mei":      {"internal/graph", "internal/identity", "internal/mcp", "internal/server", "internal/evidence", "internal/daemon", "pkg/..."},
	"cmd/meiosisd": {"internal/graph", "internal/identity", "internal/mcp", "internal/server", "internal/evidence", "internal/cli", "pkg/..."},
}

// storageBackends are the only implementations of pkg/storage. Code outside the
// composition roots must use the interface, so a second backend is a change in
// one place.
var storageBackendAllowedIn = map[string]bool{
	"internal/daemon":   true,
	"internal/cli":      true, // opens the store for every command
	"internal/server":   true,
	"internal/pushhook": true, // a separate process, opens its own handle
}

type pkgInfo struct {
	ImportPath string
	Imports    []string
}

func listPackages(t *testing.T) []pkgInfo {
	t.Helper()
	out, err := exec.Command("go", "list", "-json", module+"...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []pkgInfo
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func matches(pattern, pkg string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/..."); ok {
		return pkg == prefix || strings.HasPrefix(pkg, prefix+"/")
	}
	return pkg == pattern
}

func TestDependencyRules(t *testing.T) {
	pkgs := listPackages(t)
	seen := 0
	for _, p := range pkgs {
		rel := strings.TrimPrefix(p.ImportPath, module)
		rules, ok := forbidden[rel]
		if !ok {
			continue
		}
		seen++
		for _, imp := range p.Imports {
			target, ours := strings.CutPrefix(imp, module)
			if !ours {
				continue
			}
			for _, rule := range rules {
				if matches(rule, target) {
					t.Errorf("%s must not import %s (see docs/architecture.md)", rel, target)
				}
			}
		}
	}
	if seen != len(forbidden) {
		t.Errorf("checked %d of %d configured packages: a package was renamed or removed; update the table", seen, len(forbidden))
	}
}

func TestStorageBackendIsOnlyImportedByCompositionRoots(t *testing.T) {
	for _, p := range listPackages(t) {
		rel := strings.TrimPrefix(p.ImportPath, module)
		if storageBackendAllowedIn[rel] || strings.HasPrefix(rel, "pkg/storage") || strings.HasPrefix(rel, "internal/acceptance") {
			continue
		}
		for _, imp := range p.Imports {
			if imp == module+"pkg/storage/sqlite" {
				t.Errorf("%s imports the SQLite backend directly; take a pkg/storage.Store instead", rel)
			}
		}
	}
}

// The CLI and daemon are the only packages allowed to talk to the network, and
// nothing may phone home (NFR-4.5); the acceptance suite checks sockets, this
// checks the import.
func TestNoHTTPClientInDomainPackages(t *testing.T) {
	for _, p := range listPackages(t) {
		rel := strings.TrimPrefix(p.ImportPath, module)
		if !strings.HasPrefix(rel, "internal/graph") && !strings.HasPrefix(rel, "internal/identity") && !strings.HasPrefix(rel, "internal/scope") && !strings.HasPrefix(rel, "pkg/spec") {
			continue
		}
		for _, imp := range p.Imports {
			if imp == "net/http" || imp == "net" {
				t.Errorf("%s imports %s; the domain core does no networking", rel, imp)
			}
		}
	}
}

// exempt packages are deliberately outside the dependency table: the top of the
// stack (the CLI may use anything), tests, tools and the specification.
var exempt = map[string]bool{
	"internal/cli":          true,
	"internal/acceptance":   true,
	"internal/architecture": true,
	"spec":                  true,
	"spec/conformance":      true,
	"tools/commitlint":      true,
}

// A new package must be placed in the layering, not left unconstrained: either
// give it rules in `forbidden` or, if it really is top-level, list it in `exempt`.
func TestEveryPackageIsClassified(t *testing.T) {
	for _, p := range listPackages(t) {
		rel := strings.TrimPrefix(p.ImportPath, module)
		if _, ok := forbidden[rel]; !ok && !exempt[rel] {
			t.Errorf("%s has no entry in the dependency table (docs/architecture.md): add rules for it", rel)
		}
	}
}
