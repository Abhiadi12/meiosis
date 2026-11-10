package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func initRepo(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "repo")
}

func TestInitBootstrapsRepository(t *testing.T) {
	root := initRepo(t)

	output := execute(t, "init", "--repo", root, "--ide", "none")

	for _, path := range []string{
		".meiosis/config.yaml",
		".meiosis/human.private.key",
		".meiosis/human.public.key",
		".meiosis/agent.private.key",
		".agents/meiosis-capability.json",
		".agents/AGENTS.md",
	} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("init did not create %s: %v", path, err)
		}
	}
	if !strings.Contains(output, "[init] done.") {
		t.Fatalf("output = %q, want init summary", output)
	}

	token, err := identity.Decode([]byte(mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json"))))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	keys, err := crypto.LoadEncodedKeyPair(mustRead(t, filepath.Join(root, ".meiosis", "human.private.key")), "")
	if err != nil {
		t.Fatalf("LoadEncodedKeyPair() error = %v", err)
	}
	if err := identity.Verify(token, keys.PublicKey, nil, token.IssuedAt); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if token.Principal != "agent:meiosis" {
		t.Fatalf("token.Principal = %q, want agent:meiosis", token.Principal)
	}
}

func TestInitIsIdempotent(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")

	firstPriv := mustRead(t, filepath.Join(root, ".meiosis", "human.private.key"))
	firstToken := mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json"))

	output := execute(t, "init", "--repo", root, "--ide", "none")
	if !strings.Contains(output, "exists:") {
		t.Fatalf("second run output = %q, want only skips", output)
	}
	if got := mustRead(t, filepath.Join(root, ".meiosis", "human.private.key")); got != firstPriv {
		t.Fatal("second run regenerated the human private key")
	}
	if got := mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json")); got != firstToken {
		t.Fatal("second run reissued the capability token")
	}
}

func TestInitForceRegeneratesSecrets(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")

	firstToken := mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json"))

	execute(t, "init", "--repo", root, "--ide", "none", "--force")
	if got := mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json")); got == firstToken {
		t.Fatal("--force did not reissue the capability token")
	}
}

func TestInitDryRunWritesNothing(t *testing.T) {
	root := initRepo(t)
	output := execute(t, "init", "--repo", root, "--ide", "none", "--dry-run")

	if !strings.Contains(output, "[init] dry run") {
		t.Fatalf("output = %q, want dry-run summary", output)
	}
	if _, err := os.Stat(root); err != nil {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dry-run wrote files: %v", names)
	}
}

func TestInitScopesBootstrapToken(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none",
		"--agent", "agent:impl-7",
		"--issuer", "human:lakin",
		"--allow", "src/**",
		"--deny", "src/secret/**",
	)

	token, err := identity.Decode([]byte(mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json"))))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if token.Principal != "agent:impl-7" || token.IssuedBy != "human:lakin" {
		t.Fatalf("token = principal %q issued by %q, want impl-7/lakin", token.Principal, token.IssuedBy)
	}
	if len(token.Scope.Allow) != 1 || token.Scope.Allow[0] != "src/**" {
		t.Fatalf("scope.Allow = %v, want [src/**]", token.Scope.Allow)
	}
	if len(token.Scope.Deny) != 1 || token.Scope.Deny[0] != "src/secret/**" {
		t.Fatalf("scope.Deny = %v, want [src/secret/**]", token.Scope.Deny)
	}
}

func TestInitSkipsUnsupportedIDE(t *testing.T) {
	root := initRepo(t)
	command := New(nil)
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"init", "--repo", root, "--ide", "intellij"})
	if err := command.Execute(); err == nil {
		t.Fatal("Execute() expected an error for an unsupported IDE")
	}
}

func TestInitWritesVSCodeMCPConfig(t *testing.T) {
	root := initRepo(t)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatalf("MkdirAll(bin) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", initServerName), []byte("#!/bin/sh\nexit 0"), 0o755); err != nil {
		t.Fatalf("WriteFile(bin/meiosisd) error = %v", err)
	}
	execute(t, "init", "--repo", root, "--ide", "vscode")

	if _, err := os.Stat(filepath.Join(root, ".vscode", "mcp.json")); err != nil {
		t.Fatalf("init did not create .vscode/mcp.json: %v", err)
	}

	raw := mustRead(t, filepath.Join(root, ".vscode", "mcp.json"))
	for _, want := range []string{
		`"meiosisd"`,
		`"type": "stdio"`,
		`"-principal"`,
		`"-db"`,
		".meiosis/meiosisd.db",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("mcp.json missing %q: %s", want, raw)
		}
	}
	if want := filepath.Join(root, "bin", initServerName); !strings.Contains(raw, want) {
		t.Fatalf("mcp.json command should point at local %s, got: %s", want, raw)
	}
}

func TestInitWritesMultipleIDEMCPConfigs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := initRepo(t)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatalf("MkdirAll(bin) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", initServerName), []byte("#!/bin/sh\nexit 0"), 0o755); err != nil {
		t.Fatalf("WriteFile(bin/meiosisd) error = %v", err)
	}
	execute(t, "init", "--repo", root, "--ide", "vscode,antigravity")

	if _, err := os.Stat(filepath.Join(root, ".vscode", "mcp.json")); err != nil {
		t.Fatalf("init did not create .vscode/mcp.json: %v", err)
	}
	agConfig := filepath.Join(homeDir(), ".gemini", "antigravity", "mcp_config.json")
	if _, err := os.Stat(agConfig); err != nil {
		t.Fatalf("init did not create %s: %v", agConfig, err)
	}
	if got := mustRead(t, filepath.Join(root, ".vscode", "mcp.json")); !strings.Contains(got, filepath.Join(root, "bin", initServerName)) {
		t.Fatalf("mcp.json should point at local %s, got: %s", filepath.Join(root, "bin", initServerName), got)
	}
	if got := mustRead(t, agConfig); !strings.Contains(got, filepath.Join(root, "bin", initServerName)) {
		t.Fatalf("mcp_config.json should point at local %s, got: %s", filepath.Join(root, "bin", initServerName), got)
	}
}

func TestInitWritesAGentsMDPointers(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")

	md := mustRead(t, filepath.Join(root, ".agents", "AGENTS.md"))
	if !strings.Contains(md, "intent_create") || !strings.Contains(md, "capability_token") {
		t.Fatalf("AGENTS.md missing tool/field guidance: %q", md)
	}
	if !strings.Contains(md, ".agents/meiosis-capability.json") {
		t.Fatalf("AGENTS.md should point at the capability token: %q", md)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func TestInitIgnoresSecretsInGitRepo(t *testing.T) {
	root := initRepo(t)
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("bin/"), 0o644); err != nil {
		t.Fatal(err)
	}

	execute(t, "init", "--repo", root, "--ide", "none")
	ignore := mustRead(t, filepath.Join(root, ".gitignore"))
	for _, want := range []string{"bin/", ".meiosis/", ".agents/meiosis-capability.json"} {
		if !strings.Contains(ignore, want) {
			t.Fatalf(".gitignore = %q, missing %q", ignore, want)
		}
	}

	execute(t, "init", "--repo", root, "--ide", "none")
	if again := mustRead(t, filepath.Join(root, ".gitignore")); again != ignore {
		t.Fatalf("second init changed .gitignore:\n%q\n%q", ignore, again)
	}
}

func TestInitLeavesNonGitDirectoryWithoutGitignore(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	if _, err := os.Stat(filepath.Join(root, ".gitignore")); err == nil {
		t.Fatal("init created .gitignore outside a git repository")
	}
}

func TestInitTokenIsShortLivedAndRepoLevel(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	token, err := identity.Decode([]byte(mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := token.ExpiresAt.Sub(token.IssuedAt); got != identity.DefaultTTL {
		t.Fatalf("token TTL = %v, want %v (NFR-4.3)", got, identity.DefaultTTL)
	}
	if token.Intent != specv1.CapabilityTokenAnyIntent {
		t.Fatalf("token.Intent = %q, want the repo-level sentinel", token.Intent)
	}
}

func TestInitReissuesExpiredToken(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none", "--ttl", "1ms")
	tokenPath := filepath.Join(root, ".agents", "meiosis-capability.json")
	first := mustRead(t, tokenPath)
	humanKey := mustRead(t, filepath.Join(root, ".meiosis", "human.private.key"))
	time.Sleep(10 * time.Millisecond)

	output := execute(t, "init", "--repo", root, "--ide", "none")
	if second := mustRead(t, tokenPath); second == first {
		t.Fatal("init kept an expired token")
	}
	if !strings.Contains(output, "expired") {
		t.Fatalf("output = %q, want a note about the expired token", output)
	}
	if mustRead(t, filepath.Join(root, ".meiosis", "human.private.key")) != humanKey {
		t.Fatal("re-issuing the token regenerated the human key")
	}
}

func TestInitAgentsMDHasNoAbsolutePaths(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	md := mustRead(t, filepath.Join(root, ".agents", "AGENTS.md"))
	if strings.Contains(md, root) || strings.Contains(md, "/home/") || strings.Contains(md, "~/") {
		t.Fatalf("AGENTS.md leaks a local path:\n%s", md)
	}
	if !strings.Contains(md, ".agents/meiosis-capability.json") {
		t.Fatalf("AGENTS.md does not point at the repo-relative token path:\n%s", md)
	}
}
