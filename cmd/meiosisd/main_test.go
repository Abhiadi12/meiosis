package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mindfire-test/meiosis/pkg/crypto"
)

func TestRunRejectsMissingFlags(t *testing.T) {
	if err := run(nil, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("run() expected error for missing required flags")
	}
}

func TestRunServesOneStdioRequest(t *testing.T) {
	issuer, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.key")
	if err := os.WriteFile(keyPath, []byte(issuer.PrivateKeyBase64()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	dbPath := filepath.Join(dir, "meiosisd.db")

	stdin := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")
	var stdout bytes.Buffer

	if err := run([]string{
		"--principal", "agent:impl-3",
		"--key", keyPath,
		"--db", dbPath,
		"--allow-unauthenticated",
	}, stdin, &stdout); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal(stdout) error = %v, output = %q", err, stdout.String())
	}
	if resp["error"] != nil {
		t.Fatalf("unexpected RPC error: %v", resp["error"])
	}
	result, _ := resp["result"].(map[string]any)
	if result["serverInfo"] == nil {
		t.Fatalf("initialize result = %#v, want a serverInfo field", resp["result"])
	}
}

// daemonRepo lays out what `mei init` leaves: a .meiosis directory holding the
// agent key, the human public key and a config.
func daemonRepo(t *testing.T, config string, withIssuerKey bool) (keyPath, dbPath, issuerPath string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".meiosis")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	agent, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "agent.private.key")
	if err := os.WriteFile(keyPath, []byte(agent.PrivateKeyBase64()), 0o600); err != nil {
		t.Fatal(err)
	}
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	issuerPath = filepath.Join(dir, "human.public.key")
	if withIssuerKey {
		human, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(issuerPath, []byte(human.PublicKeyBase64()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return keyPath, filepath.Join(dir, "meiosisd.db"), issuerPath
}

func toolCallWithoutToken() *strings.Reader {
	return strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"intent_list","arguments":{}}}` + "\n")
}

func TestDaemonEnforcesTokensByDefaultWhenInitHasRun(t *testing.T) {
	keyPath, dbPath, _ := daemonRepo(t, "strict: true\n", true)
	var stdout bytes.Buffer
	if err := run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath}, toolCallWithoutToken(), &stdout); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	// The human.public.key beside the database was picked up with no flag, so a
	// call with no capability token is refused.
	if !strings.Contains(stdout.String(), "capability_token is required") {
		t.Fatalf("response = %s, want the call refused for lacking a token", stdout.String())
	}
}

func TestDaemonRefusesToStartWithoutAnIssuerKeyUnlessToldTo(t *testing.T) {
	keyPath, dbPath, _ := daemonRepo(t, "", false)
	err := run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "capability enforcement is required") || !strings.Contains(err.Error(), "--allow-unauthenticated") {
		t.Fatalf("run() with no issuer key = %v, want a refusal that names the opt-out", err)
	}

	// An explicit opt-out works in a repository that is not strict.
	var stdout bytes.Buffer
	if err := run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath, "--allow-unauthenticated"}, toolCallWithoutToken(), &stdout); err != nil {
		t.Fatalf("run() with --allow-unauthenticated = %v", err)
	}
	if strings.Contains(stdout.String(), "capability_token is required") {
		t.Fatalf("with enforcement off the call should not need a token: %s", stdout.String())
	}
}

func TestStrictRepositoryForbidsRunningWithoutEnforcement(t *testing.T) {
	keyPath, dbPath, _ := daemonRepo(t, "repo: .\nstrict: true\n", false)
	err := run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath, "--allow-unauthenticated"}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "strict: true") {
		t.Fatalf("--allow-unauthenticated in a strict repository = %v, want a refusal citing strict mode", err)
	}
	// Even with an issuer key present, opting out is refused: strict means strict.
	keyPath, dbPath, _ = daemonRepo(t, "strict: true\n", true)
	if err = run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath, "--allow-unauthenticated"}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("--allow-unauthenticated was accepted in a strict repository that has an issuer key")
	}
}

func TestStrictFalseOrMissingConfigDoesNotBlockTheOptOut(t *testing.T) {
	for name, config := range map[string]string{"strict false": "strict: false\n", "no strict key": "repo: .\n", "malformed": "::: not yaml"} {
		keyPath, dbPath, _ := daemonRepo(t, config, false)
		if err := run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath, "--allow-unauthenticated"}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
			t.Errorf("%s: run() error = %v", name, err)
		}
	}
}

func TestExplicitIssuerKeyOverridesTheOneBesideTheDatabase(t *testing.T) {
	keyPath, dbPath, _ := daemonRepo(t, "", true)
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(filepath.Dir(dbPath), "other.public.key")
	if err := os.WriteFile(explicit, []byte(other.PublicKeyBase64()), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"--principal", "agent:impl-3", "--key", keyPath, "--db", dbPath, "--issuer-pubkey", explicit}, toolCallWithoutToken(), &stdout); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "capability_token is required") {
		t.Fatalf("response = %s", stdout.String())
	}
}
