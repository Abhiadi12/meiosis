package cli

import (
	"bytes"
	"crypto/ed25519"
	_ "embed" // go:embed of the AGENTS.md template
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
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
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // world-readable by design: not secret
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
			return nil //nolint:nilerr // outside a git repository there is no .gitignore to maintain
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
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // world-readable by design: not secret
		return fmt.Errorf("init: write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(w.out, "updated: %s (ignore %s)\n", relHome(path), strings.Join(missing, ", "))
	return nil
}
