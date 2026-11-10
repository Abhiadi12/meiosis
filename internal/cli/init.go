package cli

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// initTokenTTL is how long the bootstrap capability token lives. It matches
// identity.DefaultTTL (NFR-4.3: short-lived by default). Re-running `mei init`
// issues a fresh token once the existing one has expired, and --ttl lengthens
// it for unattended setups.
const initTokenTTL = identity.DefaultTTL

// initDefaults keeps the few tunables of the bootstrap in one place.
const (
	initIDEDirName = ".gemini/antigravity"
	initServerName = "meiosisd"
)

type initOptions struct {
	repo   string
	ide    string
	agent  string
	issuer string
	force  bool
	dryRun bool
	ttl    time.Duration
	allow  []string
	deny   []string
	strict bool
}

// newInitCommand builds the "init" command tree: repo-local bootstrap
// (identity keys, capability token, .agents/AGENTS.md) plus, optionally,
// registration of meiosisd as an MCP server in a local IDE's global config.
// It is the git-init equivalent for a meiosis repo: one command, idempotent,
// nothing for the user to hand-edit.
func newInitCommand(settings *Settings) *cobra.Command {
	opts := &initOptions{ttl: initTokenTTL, strict: true}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Bootstrap a repository: identity keys, capability token, agent instructions, IDE MCP registration",
		Long: `init wires meiosis into a repository and the local agent runtime.

It generates fresh identity keys when none exist, issues a capability token
scoping the agent principal, writes .agents/AGENTS.md that any agent loads to
learn how to call the MCP tools, and registers meiosisd in the configured
IDE's global MCP config (currently: the Antigravity IDE).

Run it again to repair a partial setup. --force regenerates secrets.
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.repo == "" {
				opts.repo = settings.Repo
			}
			return runInit(cmd.OutOrStdout(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.repo, "repo", "", "repository to bootstrap (default: configured repo)")
	flags.StringVar(&opts.ide, "ide", "", "IDE(s) to register meiosisd in: vscode, antigravity, none, comma-separated (e.g. vscode,antigravity), or empty to auto-detect")
	flags.StringVar(&opts.agent, "agent", "", "agent principal the capability is granted to (default: agent:meiosis)")
	flags.StringVar(&opts.issuer, "issuer", "", "issuing human principal (default: human:<username>)")
	flags.BoolVar(&opts.force, "force", false, "regenerate secrets and overwrite generated files")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "print what would be written without writing anything")
	flags.DurationVar(&opts.ttl, "ttl", initTokenTTL, "capability token lifetime")
	flags.BoolVar(&opts.strict, "strict", true, "record strict mode in the repository config: the daemon will refuse to run without capability enforcement")
	flags.StringArrayVar(&opts.allow, "allow", nil, "glob the bootstrap token may touch (repeatable; default **)")
	flags.StringArrayVar(&opts.deny, "deny", nil, "glob the bootstrap token may not touch, even if allowed (repeatable)")

	return cmd
}

func runInit(out io.Writer, opts *initOptions) error {
	root, err := filepath.Abs(opts.repo)
	if err != nil {
		return fmt.Errorf("init: resolve repo path: %w", err)
	}

	agent := opts.agent
	if agent == "" {
		agent = "agent:meiosis"
	}
	issuer := opts.issuer
	if issuer == "" {
		name, nameErr := defaultHumanName()
		if nameErr != nil {
			return nameErr
		}
		issuer = "human:" + name
	}

	meiosisDir := filepath.Join(root, ".meiosis")
	agentsDir := filepath.Join(root, ".agents")

	humanPriv := filepath.Join(meiosisDir, "human.private.key")
	humanPub := filepath.Join(meiosisDir, "human.public.key")
	agentPriv := filepath.Join(meiosisDir, "agent.private.key")
	tokenPath := filepath.Join(agentsDir, "meiosis-capability.json")
	agentsMD := filepath.Join(agentsDir, "AGENTS.md")

	writer := &bootstrapWriter{out: out, dry: opts.dryRun}

	if writeErr := writeConfigFile(writer, filepath.Join(meiosisDir, "config.yaml"), opts.force, opts.strict); writeErr != nil {
		return writeErr
	}

	humanKeys, err := ensureKeyPair(writer, humanPriv, humanPub, opts.force)
	if err != nil {
		return err
	}
	agentKeys, err := ensureKeyPair(writer, agentPriv, filepath.Join(meiosisDir, "agent.public.key"), opts.force)
	if err != nil {
		return err
	}

	if err = ensureGitignore(writer, root); err != nil {
		return err
	}

	token, err := ensureToken(writer, tokenPath, humanKeys, agentKeys.PublicKey, opts, agent, issuer)
	if err != nil {
		return err
	}

	if agentsErr := writeAgentsMD(writer, agentsMD, tokenPath, agentsDir, opts.force, opts); agentsErr != nil {
		return agentsErr
	}

	binPath := filepath.Join(root, "bin", initServerName)
	if opts.ide != "none" {
		if binPath, err = ensureDaemonBinary(writer, root); err != nil {
			return err
		}
	}

	if err := writeIDEMCPConfig(writer, opts, homeDir(), root, binPath, agent, agentPriv, humanPub); err != nil {
		return err
	}

	printInitSummary(out, opts.dryRun, opts.ide, root, issuer, agent, tokenPath, token)
	return nil
}

type bootstrapWriter struct {
	out io.Writer
	dry bool
}

func (w *bootstrapWriter) write(path string, data []byte, perm os.FileMode, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		_, _ = fmt.Fprintf(w.out, "exists:  %s\n", relHome(path))
		return nil
	}
	if w.dry {
		_, _ = fmt.Fprintf(w.out, "would write: %s\n", relHome(path))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("init: create directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("init: write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(w.out, "wrote:   %s\n", relHome(path))
	return nil
}

func writeConfigFile(w *bootstrapWriter, path string, force, strict bool) error {
	content := fmt.Sprintf("repo: .\nformat: text\nverbose: false\nstrict: %t\n# Credentials found in pushes: off, warn or block (block refuses pushes with high-confidence matches).\nsecrets: warn\n", strict)
	if _, err := os.Stat(path); err == nil {
		if !force {
			_, _ = fmt.Fprintf(w.out, "exists:  %s\n", relHome(path))
			return nil
		}
		_, _ = fmt.Fprintf(w.out, "would rewrite: %s\n", relHome(path))
		if !w.dry {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return fmt.Errorf("init: rewrite %s: %w", path, err)
			}
			_, _ = fmt.Fprintf(w.out, "wrote:   %s\n", relHome(path))
		}
		return nil
	}
	return w.write(path, []byte(content), 0o644, force)
}

func ensureKeyPair(w *bootstrapWriter, privPath, pubPath string, force bool) (crypto.KeyPair, error) {
	if data, err := os.ReadFile(privPath); err == nil && !force {
		keys, err := crypto.LoadEncodedKeyPair(string(data), "")
		if err != nil {
			return crypto.KeyPair{}, fmt.Errorf("init: load existing key %s: %w", privPath, err)
		}
		_, _ = fmt.Fprintf(w.out, "exists:  %s\n", relHome(privPath))
		return keys, nil
	}
	if w.dry {
		_, _ = fmt.Fprintf(w.out, "would write: %s\n", relHome(privPath))
		return crypto.KeyPair{}, nil
	}
	keys, err := crypto.GenerateKeyPair()
	if err != nil {
		return crypto.KeyPair{}, fmt.Errorf("init: generate keypair: %w", err)
	}
	if err := w.write(privPath, []byte(keys.PrivateKeyBase64()), 0o600, force); err != nil {
		return crypto.KeyPair{}, err
	}
	if pubPath != "" {
		if err := w.write(pubPath, []byte(keys.PublicKeyBase64()), 0o644, force); err != nil {
			return crypto.KeyPair{}, err
		}
	}
	return keys, nil
}

func ensureToken(w *bootstrapWriter, tokenPath string, human crypto.KeyPair, agentPub ed25519.PublicKey, opts *initOptions, agent, issuer string) (specv1.CapabilityToken, error) {
	if data, err := os.ReadFile(tokenPath); err == nil && !opts.force {
		token, err := identity.Decode(data)
		if err != nil {
			return specv1.CapabilityToken{}, fmt.Errorf("init: decode existing token %s: %w", tokenPath, err)
		}
		// A token that names no holder key, or the wrong one, could not be
		// delegated from, so it is replaced along with an expired one.
		holderOK := len(agentPub) == 0 || token.HolderKey == base64.StdEncoding.EncodeToString(agentPub)
		if !token.Expired(time.Now()) && holderOK {
			_, _ = fmt.Fprintf(w.out, "exists:  %s\n", relHome(tokenPath))
			return token, nil
		}
		reason := "expired"
		if !holderOK {
			reason = "has no holder key for this agent, so it could not be delegated"
		}
		_, _ = fmt.Fprintf(w.out, "replacing: %s (%s)\n", relHome(tokenPath), reason)
		opts = &initOptions{repo: opts.repo, ide: opts.ide, agent: opts.agent, issuer: opts.issuer, dryRun: opts.dryRun, ttl: opts.ttl, allow: opts.allow, deny: opts.deny, force: true}
	}

	if opts.dryRun {
		_, _ = fmt.Fprintf(w.out, "would write: %s\n", relHome(tokenPath))
		return specv1.CapabilityToken{}, nil
	}

	allow := opts.allow
	if len(allow) == 0 {
		allow = []string{"**"}
	}
	token, err := identity.Issue(identity.IssueParams{
		Principal: agent,
		Intent:    specv1.CapabilityTokenAnyIntent,
		IssuedBy:  issuer,
		Scope:     specv1.Scope{Allow: allow, Deny: opts.deny, Mode: specv1.ScopeModeEnforce},
		TTL:       opts.ttl,
		HolderKey: agentPub,
	}, human.PrivateKey)
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("init: issue capability token: %w", err)
	}

	encoded, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("init: encode token: %w", err)
	}
	if err := w.write(tokenPath, encoded, 0o600, opts.force); err != nil {
		return specv1.CapabilityToken{}, err
	}
	return token, nil
}

// agentsTemplate is the instruction file written to .agents/AGENTS.md. It lives
// in templates/ as a real Markdown file so it can be read and edited as one.
//
//go:embed templates/agents.md.tmpl
var agentsTemplateText string

var agentsTemplate = template.Must(template.New("agents.md").Option("missingkey=error").Parse(agentsTemplateText))

func writeAgentsMD(w *bootstrapWriter, path, tokenPath, agentsDir string, force bool, opts *initOptions) error {
	allow := strings.Join(opts.allow, ", ")
	if allow == "" {
		allow = "**"
	}
	deny := strings.Join(opts.deny, ", ")
	if deny == "" {
		deny = "(none)"
	}
	scope := fmt.Sprintf("allows: %s ; denies: %s", allow, deny)

	// Paths in the generated file are relative to the repository root so the
	// file is portable between machines and never leaks the local home dir.
	relToken := tokenPath
	if rel, relErr := filepath.Rel(filepath.Dir(agentsDir), tokenPath); relErr == nil {
		relToken = filepath.ToSlash(rel)
	}

	var content bytes.Buffer
	if err := agentsTemplate.Execute(&content, map[string]string{"Server": initServerName, "Token": relToken, "Scope": scope}); err != nil {
		return fmt.Errorf("init: render AGENTS.md: %w", err)
	}

	if _, err := os.Stat(path); err == nil && !force {
		_, _ = fmt.Fprintf(w.out, "exists:  %s\n", relHome(path))
		return nil
	}
	return w.write(path, content.Bytes(), 0o644, force)
}

// ensureDaemonBinary builds bin/meiosisd when it is missing and a Go module
// is present. A missing toolchain (or no module, e.g. in tests) skips build.
func ensureDaemonBinary(w *bootstrapWriter, root string) (string, error) {
	binPath := filepath.Join(root, "bin", initServerName)
	if fi, err := os.Stat(binPath); err == nil && fi.Mode().IsRegular() {
		_, _ = fmt.Fprintf(w.out, "exists:  %s\n", relHome(binPath))
		return binPath, nil
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		if resolved, err := exec.LookPath(initServerName); err == nil {
			abs, err := filepath.Abs(resolved)
			if err != nil {
				abs = resolved
			}
			_, _ = fmt.Fprintf(w.out, "using:   %s (installed binary)\n", relHome(abs))
			return abs, nil
		}
		return "", fmt.Errorf("init: %s not found in %s or on PATH — run `make install` before init in a non-Go directory",
			initServerName, relHome(filepath.Join(root, "bin")))
	}
	if w.dry {
		_, _ = fmt.Fprintf(w.out, "would build: %s\n", relHome(binPath))
		return binPath, nil
	}
	_, _ = fmt.Fprintf(w.out, "building %s...\n", relHome(binPath))
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/meiosisd")
	cmd.Dir = root
	cmd.Stdout = w.out
	cmd.Stderr = w.out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("init: build meiosisd: %w (run `make build` to get the binaries)", err)
	}
	_, _ = fmt.Fprintf(w.out, "wrote:   %s\n", relHome(binPath))
	return binPath, nil
}

func writeIDEMCPConfig(w *bootstrapWriter, opts *initOptions, home, root, binPath, agent, agentPriv, humanPub string) error {
	ide := opts.ide

	if ide == "" {
		antigravityDir := filepath.Join(home, initIDEDirName)
		_, agErr := os.Stat(antigravityDir)
		hasAG := agErr == nil
		_, vsErr := os.Stat(filepath.Join(root, ".vscode"))
		hasVS := vsErr == nil
		switch {
		case hasAG && hasVS:
			ide = "vscode,antigravity"
		case hasAG:
			ide = "antigravity"
		case hasVS:
			ide = "vscode"
		default:
			_, _ = fmt.Fprintf(w.out, "no IDE detected — rerun with --ide vscode or --ide antigravity to register\n")
			return nil
		}
	}
	if ide == "none" {
		_, _ = fmt.Fprintln(w.out, "skipping IDE MCP registration (--ide none)")
		return nil
	}

	for _, name := range strings.Split(ide, ",") {
		name = strings.TrimSpace(name)
		switch name {
		case "antigravity":
			if err := writeAntigravityConfig(w, opts, home, root, binPath, agent, agentPriv, humanPub); err != nil {
				return err
			}
		case "vscode":
			if err := writeVSCodeConfig(w, opts, root, binPath, agent, agentPriv, humanPub); err != nil {
				return err
			}
		default:
			return fmt.Errorf("init: unsupported IDE %q (supported: vscode, antigravity, or both e.g. --ide vscode,antigravity)", name)
		}
	}
	return nil
}

func writeAntigravityConfig(w *bootstrapWriter, opts *initOptions, home, root, binPath, agent, agentPriv, humanPub string) error {
	ideDir := filepath.Join(home, initIDEDirName)
	cfgPath := filepath.Join(ideDir, "mcp_config.json")
	server := map[string]any{
		"command": binPath,
		"args": []string{
			"-principal", agent,
			"-key", agentPriv,
			"-db", filepath.Join(root, ".meiosis", "meiosisd.db"),
			"-issuer-pubkey", humanPub,
		},
	}

	cfg := map[string]any{"mcpServers": map[string]any{}}
	if existing, err := os.ReadFile(cfgPath); err == nil && len(existing) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(existing, &parsed); err != nil {
			return fmt.Errorf("init: %s exists but is not valid JSON — merge the server manually: %w", cfgPath, err)
		}
		cfg = parsed
	}
	servers, ok := cfg["mcpServers"].(map[string]any)
	if !ok {
		servers = map[string]any{}
	}
	servers[initServerName] = server
	cfg["mcpServers"] = servers

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("init: encode MCP config: %w", err)
	}
	return w.write(cfgPath, encoded, 0o644, opts.force)
}

func writeVSCodeConfig(w *bootstrapWriter, opts *initOptions, root, binPath, agent, agentPriv, humanPub string) error {
	vscodeDir := filepath.Join(root, ".vscode")
	cfgPath := filepath.Join(vscodeDir, "mcp.json")

	dbPath := filepath.Join(".meiosis", "meiosisd.db")

	server := map[string]any{
		"type":    "stdio",
		"command": binPath,
		"args": []string{
			"-principal", agent,
			"-key", agentPriv,
			"-db", dbPath,
			"-issuer-pubkey", humanPub,
		},
	}

	cfg := map[string]any{"inputs": []any{}, "servers": map[string]any{}}
	if existing, err := os.ReadFile(cfgPath); err == nil && len(existing) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(existing, &parsed); err != nil {
			return fmt.Errorf("init: %s exists but is not valid JSON — merge the server manually: %w", cfgPath, err)
		}
		cfg = parsed
	}
	servers, ok := cfg["servers"].(map[string]any)
	if !ok {
		servers = map[string]any{}
	}
	servers[initServerName] = server
	cfg["servers"] = servers

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("init: encode MCP config: %w", err)
	}

	if err := os.MkdirAll(vscodeDir, 0o755); err != nil {
		return fmt.Errorf("init: create %s: %w", vscodeDir, err)
	}
	return w.write(cfgPath, encoded, 0o644, opts.force)
}

func printInitSummary(out io.Writer, dry bool, ide, root, issuer, agent, tokenPath string, token specv1.CapabilityToken) {
	if dry {
		_, _ = fmt.Fprint(out, "\n[init] dry run: nothing was written.\n")
		return
	}
	_, _ = fmt.Fprint(out, "\n[init] done.\n")
	_, _ = fmt.Fprintf(out, "  repository : %s\n", relHome(root))
	_, _ = fmt.Fprintf(out, "  agent      : %s  (daemon principal, MCP)\n", agent)
	_, _ = fmt.Fprintf(out, "  issuer     : %s  (human, signs capability tokens)\n", issuer)
	_, _ = fmt.Fprintf(out, "  token      : %s\n", relHome(tokenPath))
	if !token.ExpiresAt.IsZero() {
		_, _ = fmt.Fprintf(out, "  token ttl  : expires %s\n", token.ExpiresAt.Format(time.RFC3339))
	}
	switch ide {
	case "none", "":
		_, _ = fmt.Fprint(out, "\nmeiosisd was not registered with an IDE (use --ide vscode or --ide antigravity).\n")
	case "vscode":
		_, _ = fmt.Fprintf(out, "\nOpen this repository in VS Code: the meiosisd server is registered in\n%s. Approve/enable the MCP server when prompted, then try:\n", relHome(filepath.Join(root, ".vscode", "mcp.json")))
		_, _ = fmt.Fprint(out, "  \"declare an intent to refactor the Button component, then check whether\n")
		_, _ = fmt.Fprint(out, "   pkg/auth/login.go is inside its scope\"\n")
	default:
		_, _ = fmt.Fprint(out, "\nThe meiosisd server is registered with your IDE(s):\n")
		for _, name := range strings.Split(ide, ",") {
			switch strings.TrimSpace(name) {
			case "vscode":
				_, _ = fmt.Fprintf(out, "  - VS Code: %s\n", relHome(filepath.Join(root, ".vscode", "mcp.json")))
			case "antigravity":
				_, _ = fmt.Fprintf(out, "  - Antigravity: %s\n", relHome(filepath.Join(homeDir(), initIDEDirName, "mcp_config.json")))
			}
		}
		_, _ = fmt.Fprint(out, "\nApprove/enable the meiosisd server when your IDE prompts, then try:\n")
		_, _ = fmt.Fprint(out, "  \"declare an intent to refactor the Button component, then check whether\n")
		_, _ = fmt.Fprint(out, "   pkg/auth/login.go is inside its scope\"\n")
	}
}

func defaultHumanName() (string, error) {
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return sanitizePrincipalPart(u.Username), nil
	}
	if env := os.Getenv("USER"); strings.TrimSpace(env) != "" {
		return sanitizePrincipalPart(env), nil
	}
	return "", fmt.Errorf("init: cannot determine a human principal (pass --issuer)")
}

func sanitizePrincipalPart(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "user"
	}
	return out
}

func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return ""
}

// relHome prints a path as given when it is outside $HOME (the common case
// for repo files) or as ~/... when it is inside it (IDE config, keys).
func relHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if relative, ok := strings.CutPrefix(path, home+string(filepath.Separator)); ok {
		return "~/" + relative
	}
	return path
}

// secretIgnoreEntries are the generated files that hold private key material
// or live credentials and must never be committed.
var secretIgnoreEntries = []string{".meiosis/", ".agents/meiosis-capability.json"}

// ensureGitignore appends any missing secretIgnoreEntries to the repository's
// .gitignore. It does nothing outside a git repository (no .git and no
// .gitignore), and never rewrites existing lines.
func ensureGitignore(w *bootstrapWriter, root string) error {
	path := filepath.Join(root, ".gitignore")
	existing, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("init: read %s: %w", path, readErr)
	}
	if os.IsNotExist(readErr) {
		if _, statErr := os.Stat(filepath.Join(root, ".git")); statErr != nil {
			return nil
		}
	}

	have := map[string]bool{}
	for _, line := range strings.Split(string(existing), "\n") {
		have[strings.TrimSpace(line)] = true
	}
	var missing []string
	for _, entry := range secretIgnoreEntries {
		if !have[entry] && !have[strings.TrimSuffix(entry, "/")] {
			missing = append(missing, entry)
		}
	}
	if len(missing) == 0 {
		_, _ = fmt.Fprintf(w.out, "exists:  %s (secrets already ignored)\n", relHome(path))
		return nil
	}
	if w.dry {
		_, _ = fmt.Fprintf(w.out, "would update: %s (ignore %s)\n", relHome(path), strings.Join(missing, ", "))
		return nil
	}
	var b strings.Builder
	b.Write(existing)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n# meiosis: private keys and capability tokens\n")
	for _, entry := range missing {
		b.WriteString(entry + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("init: write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(w.out, "updated: %s (ignore %s)\n", relHome(path), strings.Join(missing, ", "))
	return nil
}
