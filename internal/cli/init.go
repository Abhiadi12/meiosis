package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/identity"
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
	return "", errors.New("init: cannot determine a human principal (pass --issuer)")
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
