package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/repoconfig"
	"github.com/mindfire-test/meiosis/internal/server"
)

// serveOptions holds the flags of `mei serve`; resolve fills the defaults that
// depend on the repository.
type serveOptions struct {
	addr, reposDir, repoName, dbPath string
	issuerPath, signerKey, signer    string
	agentKey, agent, gitBin          string
	allowUnauth                      bool
	noInit                           bool
	secretsMode                      string
}

func newServeCommand(settings *Settings) *cobra.Command {
	var o serveOptions
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
			return o.run(cmd, root)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&o.addr, "addr", "127.0.0.1:8484", "address to listen on")
	flags.StringVar(&o.repoName, "name", "", "repository name (default: this directory's name)")
	flags.StringVar(&o.reposDir, "repos-dir", "", "where the bare repositories live (default: <repo>/.meiosis/git)")
	flags.StringVar(&o.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	flags.StringVar(&o.issuerPath, "issuer-pubkey", "", "trusted issuer public key (default: <repo>/.meiosis/human.public.key)")
	flags.StringVar(&o.secretsMode, "secrets", "", "credential scanning of pushes: off, warn or block (default: the repository config, else warn)")
	flags.BoolVar(&o.noInit, "no-init", false, "do not set the repository up on first run; fail instead")
	flags.BoolVar(&o.allowUnauth, "allow-unauthenticated", false, "serve without capability tokens (refused in a strict repository)")
	flags.StringVar(&o.signerKey, "signer-key", "", "key that signs ref update records (default: <repo>/.meiosis/human.private.key)")
	flags.StringVar(&o.signer, "signer", "", "principal for --signer-key (default: human:<username>)")
	flags.StringVar(&o.agentKey, "agent-key", "", "key the /mcp endpoint signs as (default: <repo>/.meiosis/agent.private.key)")
	flags.StringVar(&o.agent, "agent", "", "principal for --agent-key (default: the one in .agents/meiosis-capability.json)")
	flags.StringVar(&o.gitBin, "git", "", "git binary (default: git on PATH)")
	return cmd
}

// resolve fills in every default that depends on the repository root.
func (o *serveOptions) resolve(root string) {
	meiosis := filepath.Join(root, ".meiosis")
	if o.dbPath == "" {
		o.dbPath = filepath.Join(meiosis, "meiosisd.db")
	}
	if o.reposDir == "" {
		o.reposDir = filepath.Join(meiosis, "git")
	}
	if o.repoName == "" {
		o.repoName = server.SanitizeRepoName(filepath.Base(root))
	}
	if o.signerKey == "" {
		o.signerKey = filepath.Join(meiosis, "human.private.key")
	}
	if o.agentKey == "" {
		o.agentKey = filepath.Join(meiosis, "agent.private.key")
	}
}

// ensureInitialised sets the repository up on first run (NFR-5.2: `mei serve`
// is the only command needed), the way `mei init --ide none` would.
func (o *serveOptions) ensureInitialised(cmd *cobra.Command, root string) error {
	if _, err := os.Stat(o.signerKey); err == nil {
		return nil
	}
	if o.noInit {
		return fmt.Errorf("no signing key at %s: run `mei init` first (--no-init was given)", o.signerKey)
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "first run in %s: setting up (as `mei init --ide none` would)\n", root)
	if err := runInit(cmd.ErrOrStderr(), &initOptions{repo: root, ide: "none", ttl: initTokenTTL, strict: true}); err != nil {
		return fmt.Errorf("first-run setup: %w", err)
	}
	return nil
}

// resolvePrincipals defaults the signer and agent principals.
func (o *serveOptions) resolvePrincipals(root string) error {
	if o.signer == "" {
		name, err := defaultHumanName()
		if err != nil {
			return err
		}
		o.signer = "human:" + name
	}
	if o.agent == "" {
		o.agent = "agent:meiosis"
		if t, err := loadToken(filepath.Join(root, ".agents", "meiosis-capability.json")); err == nil {
			o.agent = t.Principal
		}
	}
	return nil
}

// checkGit fails early when the git binary the server needs is missing.
func (o *serveOptions) checkGit() error {
	bin := o.gitBin
	if bin == "" {
		bin = "git"
	}
	if _, err := exec.LookPath(bin); err != nil {
		if o.gitBin != "" {
			return fmt.Errorf("git binary %q not found: %w", o.gitBin, err)
		}
		return fmt.Errorf("serving repositories needs git on PATH: %w", err)
	}
	return nil
}

func (o *serveOptions) run(cmd *cobra.Command, root string) error {
	o.resolve(root)
	if err := o.ensureInitialised(cmd, root); err != nil {
		return err
	}
	if err := o.resolvePrincipals(root); err != nil {
		return err
	}
	if err := o.checkGit(); err != nil {
		return err
	}
	issuer, strict, err := repoconfig.ResolveEnforcement(o.issuerPath, o.dbPath, o.allowUnauth, cmd.ErrOrStderr())
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
	if o.secretsMode == "" {
		o.secretsMode = repoconfig.SecretsMode(filepath.Dir(o.dbPath))
	}
	srv, err := server.New(server.Config{
		Addr: o.addr, ReposDir: o.reposDir, Repos: []string{o.repoName}, DB: o.dbPath, Mei: self, Git: o.gitBin,
		SignerKeyPath: o.signerKey, Signer: o.signer, IssuerKeyPath: issuer, Strict: strict, Secrets: o.secretsMode,
		Agent: o.agent, AgentKeyPath: o.agentKey, Version: Version,
	})
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o.banner(cmd.ErrOrStderr(), issuer, strict)
	return srv.Serve(ctx)
}

// banner tells the user what is being served and how it is protected.
func (o *serveOptions) banner(out io.Writer, issuer string, strict bool) {
	base := "http://" + o.addr
	_, _ = fmt.Fprintf(out, "meiosis serving %q on %s\n", o.repoName, base)
	_, _ = fmt.Fprintf(out, "  git  : %s/%s.git\n  mcp  : %s/mcp (acts as %s)\n", base, o.repoName, base, o.agent)
	switch {
	case issuer == "":
		_, _ = fmt.Fprintln(out, "  auth : NONE (--allow-unauthenticated): anyone who can reach this address can push")
	case strict:
		_, _ = fmt.Fprintln(out, "  auth : capability tokens required (strict)")
	default:
		_, _ = fmt.Fprintln(out, "  auth : capability tokens required")
	}
	if host, _, ok := strings.Cut(o.addr, ":"); ok && host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
		_, _ = fmt.Fprintln(out, "  note : this address is not loopback; tokens are bearer credentials, so put TLS in front of it")
	}
	_, _ = fmt.Fprintf(out, "  scan : credentials in pushes: %s\n", o.secretsMode)
	_, _ = fmt.Fprintf(out, "  next : mei remote add meiosis --url %s/%s.git && git push meiosis main\n", base, o.repoName)
}
