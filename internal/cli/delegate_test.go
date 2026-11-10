package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

func initedRepo(t *testing.T, extra ...string) string {
	t.Helper()
	root := initRepo(t)
	mustRun(t, "", append([]string{"init", "--repo", root, "--ide", "none"}, extra...)...)
	return root
}

func rootToken(t *testing.T, root string) specv1.CapabilityToken {
	t.Helper()
	token, err := identity.Decode([]byte(mustRead(t, filepath.Join(root, ".agents", "meiosis-capability.json"))))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestInitIssuesADelegableTokenAndRecordsStrictMode(t *testing.T) {
	root := initedRepo(t)
	token := rootToken(t, root)
	agentPub := strings.TrimSpace(mustRead(t, filepath.Join(root, ".meiosis", "agent.public.key")))
	if token.HolderKey != agentPub {
		t.Fatalf("token holder key = %q, want the agent's public key %q", token.HolderKey, agentPub)
	}
	if !strings.Contains(mustRead(t, filepath.Join(root, ".meiosis", "config.yaml")), "strict: true") {
		t.Fatal("init should record strict: true by default")
	}

	loose := initedRepo(t, "--strict=false")
	if !strings.Contains(mustRead(t, filepath.Join(loose, ".meiosis", "config.yaml")), "strict: false") {
		t.Fatal("--strict=false was not recorded")
	}
}

func TestInitReplacesATokenThatCannotBeDelegated(t *testing.T) {
	root := initedRepo(t)
	tokenPath := filepath.Join(root, ".agents", "meiosis-capability.json")
	human, err := crypto.LoadEncodedKeyPair(mustRead(t, filepath.Join(root, ".meiosis", "human.private.key")), "")
	if err != nil {
		t.Fatal(err)
	}
	// An old-style token: valid, but issued without a holder key.
	old, err := identity.Issue(identity.IssueParams{
		Principal: "agent:meiosis", IssuedBy: "human:x", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
	}, human.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := identity.Encode(old)
	if err := os.WriteFile(tokenPath, enc, 0o600); err != nil {
		t.Fatal(err)
	}

	out := mustRun(t, "", "init", "--repo", root, "--ide", "none")
	if !strings.Contains(out, "replacing") || !strings.Contains(out, "holder key") {
		t.Fatalf("init output = %s", out)
	}
	if rootToken(t, root).HolderKey == "" {
		t.Fatal("the replacement token still has no holder key")
	}
}

func TestAuthorizeCanSetHolderKeyOperationsAndSpendCeiling(t *testing.T) {
	issuer, keyPath := writeIssuerKey(t)
	holder, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	holderPath := filepath.Join(t.TempDir(), "holder.pub")
	if err = os.WriteFile(holderPath, []byte(holder.PublicKeyBase64()), 0o644); err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, "", "intent", "authorize", "--principal", "agent:impl-3", "--intent", "int_"+strings.Repeat("a", 52),
		"--issuer", "human:lakin", "--issuer-key", keyPath, "--allow", "src/**",
		"--holder-key", holderPath, "--operation", "attempt_open", "--operation", "attempt_write", "--spend-ceiling", "250")
	token, err := identity.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if token.HolderKey != holder.PublicKeyBase64() || len(token.Operations) != 2 || token.SpendCeilingMicros == nil || *token.SpendCeilingMicros != 250 {
		t.Fatalf("token = %+v", token)
	}
	if err := identity.Verify(token, issuer.PublicKey, nil, time.Now()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if _, err := run("", "intent", "authorize", "--principal", "agent:x", "--intent", "int_"+strings.Repeat("a", 52), "--issuer", "human:l", "--issuer-key", keyPath, "--allow", "**", "--operation", "not_a_tool"); err == nil {
		t.Fatal("an unknown operation was accepted")
	}
}

func TestDelegateIssuesANarrowerTokenAndAKeyForTheSubAgent(t *testing.T) {
	root := initedRepo(t, "--allow", "src/**", "--allow", "docs/**", "--deny", "src/secret/**")
	dir := t.TempDir()
	subKey, out := filepath.Join(dir, "tests-1.key"), filepath.Join(dir, "tests-1.token.json")
	parentPath := filepath.Join(root, ".agents", "meiosis-capability.json")
	agentKey := filepath.Join(root, ".meiosis", "agent.private.key")

	msg := mustRun(t, "", "intent", "delegate", "--repo", root, "--token", parentPath, "--key", agentKey, "--to", "agent:tests-1",
		"--generate-key", subKey, "--allow", "src/auth/**", "--operation", "attempt_write", "--spend-ceiling", "5000", "--out", out)
	if !strings.Contains(msg, "agent:tests-1 <- agent:meiosis <- human:") {
		t.Fatalf("output = %s, want the chain to the human", msg)
	}

	child, err := identity.Decode([]byte(mustRead(t, out)))
	if err != nil {
		t.Fatal(err)
	}
	human, _ := crypto.LoadEncodedPublicKey(mustRead(t, filepath.Join(root, ".meiosis", "human.public.key")))
	if err = identity.Verify(child, human, nil, time.Now()); err != nil {
		t.Fatalf("the delegated token does not verify: %v", err)
	}
	if child.Parent == nil || child.Principal != "agent:tests-1" || child.Scope.Allow[0] != "src/auth/**" || len(child.Scope.Deny) != 1 {
		t.Fatalf("child = %+v, want the narrowed allow and the parent's deny carried over", child)
	}
	// The generated private key matches the holder key the token names.
	keyData, err := os.ReadFile(subKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := crypto.LoadEncodedKeyPair(string(keyData), "")
	if err != nil || child.HolderKey != base64.StdEncoding.EncodeToString(pair.PublicKey) {
		t.Fatalf("generated key does not match the token's holder key: %v", err)
	}
	if info, _ := os.Stat(subKey); info.Mode().Perm() != 0o600 {
		t.Fatalf("the sub-agent's private key has mode %v, want 0600", info.Mode().Perm())
	}
}

func TestDelegateRefusesToWidenAndLeavesNoKeyBehind(t *testing.T) {
	root := initedRepo(t, "--allow", "src/**", "--deny", "src/secret/**")
	dir := t.TempDir()
	subKey := filepath.Join(dir, "k")
	base := []string{
		"intent", "delegate", "--repo", root, "--token", filepath.Join(root, ".agents", "meiosis-capability.json"),
		"--key", filepath.Join(root, ".meiosis", "agent.private.key"), "--to", "agent:x",
	}

	for name, extra := range map[string][]string{
		"wider paths":     {"--generate-key", subKey, "--allow", "**"},
		"outside paths":   {"--generate-key", subKey, "--allow", "lib/**"},
		"relaxed mode":    {"--generate-key", subKey, "--mode", "warn"},
		"longer lifetime": {"--generate-key", subKey, "--ttl", "720h"},
	} {
		_, err := run("", append(append([]string{}, base...), extra...)...)
		if err == nil || !strings.Contains(err.Error(), "widen") {
			t.Errorf("%s: error = %v, want a widening refusal", name, err)
		}
	}
	if _, err := os.Stat(subKey); err == nil {
		t.Fatal("a refused delegation left a generated private key behind")
	}
}

func TestDelegateRefusesBadInputs(t *testing.T) {
	root := initedRepo(t)
	good := []string{
		"intent", "delegate", "--repo", root, "--token", filepath.Join(root, ".agents", "meiosis-capability.json"),
		"--key", filepath.Join(root, ".meiosis", "agent.private.key"), "--to", "agent:x",
	}
	humanKey := filepath.Join(root, ".meiosis", "human.private.key")

	if _, err := run("", "intent", "delegate", "--repo", root); err == nil {
		t.Error("missing --token/--key/--to accepted")
	}
	pub := filepath.Join(root, ".meiosis", "agent.public.key")
	if _, err := run("", append(append([]string{}, good...), "--holder-key", pub, "--generate-key", filepath.Join(t.TempDir(), "k"))...); err == nil {
		t.Error("--holder-key with --generate-key accepted")
	}
	// Only the holder may delegate: the human's key is not the agent's.
	args := append([]string{}, good...)
	args[6] = "--key"
	args[7] = humanKey
	if _, err := run("", append(args, "--holder-key", pub)...); err == nil || !strings.Contains(err.Error(), "only the holder") {
		t.Errorf("delegating with someone else's key = %v", err)
	}
	// A parent that does not verify against the repository's issuer is refused up front.
	stranger, _ := crypto.GenerateKeyPair()
	strangerPub := filepath.Join(t.TempDir(), "stranger.pub")
	if err := os.WriteFile(strangerPub, []byte(stranger.PublicKeyBase64()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run("", append(append([]string{}, good...), "--holder-key", pub, "--issuer-pubkey", strangerPub)...); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("delegating from a token the issuer never signed = %v", err)
	}
	// Delegating with the plain default succeeds and prints the token as JSON.
	out := mustRun(t, "", append(append([]string{}, good...), "--holder-key", pub)...)
	var tok map[string]any
	if err := json.Unmarshal([]byte(out), &tok); err != nil || tok["parent"] == nil {
		t.Fatalf("stdout is not a delegated token: %v\n%s", err, out)
	}
}

func TestChainShowsWhoAuthorisedEachWrite(t *testing.T) {
	root := initedRepo(t)
	parent := rootToken(t, root)
	agent, err := crypto.LoadEncodedKeyPair(mustRead(t, filepath.Join(root, ".meiosis", "agent.private.key")), "")
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := crypto.GenerateKeyPair()
	child, err := identity.Delegate(parent, identity.DelegateParams{Principal: "agent:tests-1", HolderKey: sub.PublicKey}, agent.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	backend, err := sqlite.Open(filepath.Join(root, ".meiosis", "meiosisd.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := graph.NewStore(backend)
	ctx := context.Background()
	if _, err = store.RecordAuthority(ctx, graph.AuthorityParams{Op: "attempt_write", Principal: "agent:tests-1", Token: child, Object: "att_one", Attempt: "att_one", Path: "src/a.go"}, sub.PrivateKey); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err = store.RecordAuthority(ctx, graph.AuthorityParams{Op: "intent_create", Principal: "agent:meiosis", Token: parent, Object: "int_two", Intent: "int_two"}, agent.PrivateKey); err != nil {
		t.Fatal(err)
	}
	// A record whose chain the repository's issuer never signed.
	stranger, _ := crypto.GenerateKeyPair()
	bogus, err := identity.Issue(identity.IssueParams{
		Principal: "agent:evil", IssuedBy: "human:mallory", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
	}, stranger.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecordAuthority(ctx, graph.AuthorityParams{Op: "attempt_open", Principal: "agent:evil", Token: bogus, Object: "att_three", Attempt: "att_three"}, stranger.PrivateKey); err != nil {
		t.Fatal(err)
	}
	_ = backend.Close()

	all := mustRun(t, "", "chain", "--repo", root)
	for _, want := range []string{"attempt_write", "src/a.go", "agent:tests-1 <- agent:meiosis <- human:", "intent_create", "verified", "FAILED"} {
		if !strings.Contains(all, want) {
			t.Errorf("chain output missing %q:\n%s", want, all)
		}
	}
	one := mustRun(t, "", "chain", "att_one", "--repo", root)
	if !strings.Contains(one, "attempt_write") || strings.Contains(one, "intent_create") || strings.Contains(one, "FAILED") {
		t.Fatalf("chain att_one = %s", one)
	}
	if byIntent := mustRun(t, "", "chain", "int_tw", "--repo", root); !strings.Contains(byIntent, "intent_create") {
		t.Fatalf("a prefix of an intent ID should match: %s", byIntent)
	}
	if none := mustRun(t, "", "chain", "att_nothing", "--repo", root); !strings.Contains(none, "no recorded writes") {
		t.Fatalf("none = %s", none)
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(mustRun(t, "", "chain", "att_one", "--repo", root, "--format", "json")), &entries); err != nil || len(entries) != 1 {
		t.Fatalf("json chain = %v, %v", entries, err)
	}
	if entries[0]["verified"] != true || len(entries[0]["chain"].([]any)) != 2 {
		t.Fatalf("entry = %v", entries[0])
	}
}
