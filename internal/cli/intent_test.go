package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

func writeIssuerKey(t *testing.T) (crypto.KeyPair, string) {
	t.Helper()
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "issuer.key")
	if err := os.WriteFile(path, []byte(keys.PrivateKeyBase64()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return keys, path
}

func TestIntentAuthorizeIssuesSignedToken(t *testing.T) {
	issuer, keyPath := writeIssuerKey(t)

	output := execute(t,
		"intent", "authorize",
		"--principal", "agent:impl-3",
		"--intent", "int_"+strings.Repeat("a", 52),
		"--issuer", "human:lakin",
		"--issuer-key", keyPath,
		"--allow", "pkg/auth/**",
	)

	token, err := identity.Decode([]byte(output))
	if err != nil {
		t.Fatalf("Decode() error = %v, output = %q", err, output)
	}
	if err := identity.Verify(token, issuer.PublicKey, nil, token.IssuedAt); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if token.Principal != "agent:impl-3" || token.IssuedBy != "human:lakin" {
		t.Fatalf("token = %+v, want principal/issuedBy to match flags", token)
	}
}

func TestIntentAuthorizeWritesToOutFile(t *testing.T) {
	_, keyPath := writeIssuerKey(t)
	outPath := filepath.Join(t.TempDir(), "token.json")

	output := execute(t,
		"intent", "authorize",
		"--principal", "agent:impl-3",
		"--intent", "int_"+strings.Repeat("a", 52),
		"--issuer", "human:lakin",
		"--issuer-key", keyPath,
		"--allow", "pkg/auth/**",
		"--out", outPath,
	)
	if output != "" {
		t.Fatalf("output = %q, want nothing written to stdout when --out is set", output)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if _, err := identity.Decode(data); err != nil {
		t.Fatalf("Decode(out file) error = %v", err)
	}
}

func TestIntentAuthorizeRequiresFlags(t *testing.T) {
	command := New(nil)
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"intent", "authorize"})
	if err := command.Execute(); err == nil {
		t.Fatal("Execute() expected an error for missing required flags")
	}
}

func TestIntentDeclareSignsAndPersists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")

	output := execute(t,
		"intent", "declare", "Refactor the Button component",
		"--repo", root,
		"--files", "src/components/Button.tsx",
		"--acceptance", "tests pass",
		"--created-by", "human:lakin",
	)
	if !strings.Contains(output, "intent int_") {
		t.Fatalf("output = %q, want a declared intent ID", output)
	}
	if !strings.Contains(output, "Refactor the Button component") {
		t.Fatalf("output = %q, want declared title", output)
	}
	if !strings.Contains(output, "src/components/Button.tsx") {
		t.Fatalf("output = %q, want files path", output)
	}
	if !strings.Contains(output, "mode enforce") {
		t.Fatalf("output = %q, want mode enforce", output)
	}
}

func TestIntentDeclareRequiresTitle(t *testing.T) {
	command := New(nil)
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"intent", "declare"})
	if err := command.Execute(); err == nil {
		t.Fatal("Execute() expected an error for a missing title")
	}
}

func TestIntentRevokeRecordsTokenInStore(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	tokenPath := filepath.Join(root, ".agents", "meiosis-capability.json")
	token, err := identity.Decode([]byte(mustRead(t, tokenPath)))
	if err != nil {
		t.Fatal(err)
	}

	output := execute(t, "intent", "revoke", "--repo", root, "--token", tokenPath)
	if !strings.Contains(output, token.ID) {
		t.Fatalf("output = %q, want the revoked token id", output)
	}
	// Idempotent.
	execute(t, "intent", "revoke", "--repo", root, token.ID)

	store, err := sqlite.Open(filepath.Join(root, ".meiosis", "meiosisd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if !identity.NewStoreRevocationList(store).IsRevoked(token.ID) {
		t.Fatal("token is not revoked in the store after `mei intent revoke`")
	}
}

func TestIntentRevokeRequiresExactlyOneTarget(t *testing.T) {
	root := initRepo(t)
	execute(t, "init", "--repo", root, "--ide", "none")
	command := New(nil)
	command.SetOut(&strings.Builder{})
	command.SetErr(&strings.Builder{})
	command.SetArgs([]string{"intent", "revoke", "--repo", root})
	if err := command.Execute(); err == nil {
		t.Fatal("revoke with no target succeeded")
	}
}
