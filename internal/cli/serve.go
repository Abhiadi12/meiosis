package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/server"
)

func newServeCommand(settings *Settings) *cobra.Command {
	var (
		addr, reposDir, repoName, dbPath string
		issuerPath, signerKey, signer    string
		agentKey, agent, gitBin          string
		allowUnauth                      bool
		noInit                           bool
		secretsMode                      string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve this repository over Git and MCP, with capability-token auth and push policy",
		Long: `Starts one process that serves:

  http://ADDR/NAME.git   the repository, for git clone / fetch / push
  http://ADDR/mcp        the MCP endpoint, as the repository's agent

Every request must carry a capability token (a bearer token, or the password of
HTTP Basic, which is how a git credential helper supplies one). Pushes are held
to the token's scope and to the scope of the intent they name with
"git push -o intent=ID"; a push that names none is accepted under an implicit
intent in warn mode. Each ref update is recorded with the world hash of the new
tree, signed by this server.

Deleting refs and rewriting history are refused. With strict: true in
.meiosis/config.yaml, as mei init leaves it, the server will not run without
tokens. Bind to a non-loopback address only behind TLS: tokens are bearer
credentials.`,
		Example: "  mei serve\n  mei remote add meiosis && git push meiosis main",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := repoRoot(settings)
			if err != nil {
				return err
			}
			meiosis := filepath.Join(root, ".meiosis")
			if dbPath == "" {
				dbPath = filepath.Join(meiosis, "meiosisd.db")
			}
			if reposDir == "" {
				reposDir = filepath.Join(meiosis, "git")
			}
			if repoName == "" {
				repoName = server.SanitizeRepoName(filepath.Base(root))
			}
			if signerKey == "" {
				signerKey = filepath.Join(meiosis, "human.private.key")
			}
			if agentKey == "" {
				agentKey = filepath.Join(meiosis, "agent.private.key")
			}
			if _, statErr := os.Stat(signerKey); statErr != nil {
				// First run (NFR-5.2): `mei serve` is the only command needed. Set up
				// the repository the way `mei init` would, without touching any IDE.
				if noInit {
					return fmt.Errorf("no signing key at %s: run `mei init` first (--no-init was given)", signerKey)
				}
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "first run in %s: setting up (as `mei init --ide none` would)\n", root)
				if initErr := runInit(cmd.ErrOrStderr(), &initOptions{repo: root, ide: "none", ttl: initTokenTTL, strict: true}); initErr != nil {
					return fmt.Errorf("first-run setup: %w", initErr)
				}
			}
			if signer == "" {
				name, nameErr := defaultHumanName()
				if nameErr != nil {
					return nameErr
				}
				signer = "human:" + name
			}
			if agent == "" {
				agent = "agent:meiosis"
				if t, tErr := loadToken(filepath.Join(root, ".agents", "meiosis-capability.json")); tErr == nil {
					agent = t.Principal
				}
			}
			if gitBin != "" {
				if _, lookErr := exec.LookPath(gitBin); lookErr != nil {
					return fmt.Errorf("git binary %q not found: %w", gitBin, lookErr)
				}
			} else if _, lookErr := exec.LookPath("git"); lookErr != nil {
				return fmt.Errorf("serving repositories needs git on PATH: %w", lookErr)
			}

			issuer, strict, err := server.ResolveEnforcement(issuerPath, dbPath, allowUnauth, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			self, err := os.Executable()
			if err != nil {
				return fmt.Errorf("find the mei binary the hooks should run: %w", err)
			}
			if resolved, evalErr := filepath.EvalSymlinks(self); evalErr == nil {
				self = resolved
			}

			if secretsMode == "" {
				secretsMode = server.RepoSecretsMode(filepath.Dir(dbPath))
			}
			srv, err := server.New(server.Config{
				Addr: addr, ReposDir: reposDir, Repos: []string{repoName}, DB: dbPath, Mei: self, Git: gitBin,
				SignerKeyPath: signerKey, Signer: signer, IssuerKeyPath: issuer, Strict: strict, Secrets: secretsMode,
				Agent: agent, AgentKeyPath: agentKey, Version: Version,
			})
			if err != nil {
				return err
			}
			defer func() { _ = srv.Close() }()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			out := cmd.ErrOrStderr()
			base := "http://" + addr
			_, _ = fmt.Fprintf(out, "meiosis serving %q on %s\n", repoName, base)
			_, _ = fmt.Fprintf(out, "  git  : %s/%s.git\n  mcp  : %s/mcp (acts as %s)\n", base, repoName, base, agent)
			switch {
			case issuer == "":
				_, _ = fmt.Fprintln(out, "  auth : NONE (--allow-unauthenticated): anyone who can reach this address can push")
			case strict:
				_, _ = fmt.Fprintln(out, "  auth : capability tokens required (strict)")
			default:
				_, _ = fmt.Fprintln(out, "  auth : capability tokens required")
			}
			if host, _, ok := strings.Cut(addr, ":"); ok && host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
				_, _ = fmt.Fprintln(out, "  note : this address is not loopback; tokens are bearer credentials, so put TLS in front of it")
			}
			_, _ = fmt.Fprintf(out, "  scan : credentials in pushes: %s\n", secretsMode)
			_, _ = fmt.Fprintf(out, "  next : mei remote add meiosis --url %s/%s.git && git push meiosis main\n", base, repoName)
			return srv.Serve(ctx)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&addr, "addr", "127.0.0.1:8484", "address to listen on")
	flags.StringVar(&repoName, "name", "", "repository name (default: this directory's name)")
	flags.StringVar(&reposDir, "repos-dir", "", "where the bare repositories live (default: <repo>/.meiosis/git)")
	flags.StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	flags.StringVar(&issuerPath, "issuer-pubkey", "", "trusted issuer public key (default: <repo>/.meiosis/human.public.key)")
	flags.StringVar(&secretsMode, "secrets", "", "credential scanning of pushes: off, warn or block (default: the repository config, else warn)")
	flags.BoolVar(&noInit, "no-init", false, "do not set the repository up on first run; fail instead")
	flags.BoolVar(&allowUnauth, "allow-unauthenticated", false, "serve without capability tokens (refused in a strict repository)")
	flags.StringVar(&signerKey, "signer-key", "", "key that signs ref update records (default: <repo>/.meiosis/human.private.key)")
	flags.StringVar(&signer, "signer", "", "principal for --signer-key (default: human:<username>)")
	flags.StringVar(&agentKey, "agent-key", "", "key the /mcp endpoint signs as (default: <repo>/.meiosis/agent.private.key)")
	flags.StringVar(&agent, "agent", "", "principal for --agent-key (default: the one in .agents/meiosis-capability.json)")
	flags.StringVar(&gitBin, "git", "", "git binary (default: git on PATH)")
	return cmd
}
