package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

	if err := os.MkdirAll(vscodeDir, 0o750); err != nil {
		return fmt.Errorf("init: create %s: %w", vscodeDir, err)
	}
	return w.write(cfgPath, encoded, 0o644, opts.force)
}
