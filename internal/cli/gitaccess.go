package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/server"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// credentialTTL is how long a token a credential helper mints lives. Git asks
// again whenever it needs one, so it can be short.
const credentialTTL = time.Hour

func newTokenCommand(settings *Settings) *cobra.Command {
	token := &cobra.Command{Use: "token", Short: "Work with capability tokens as credentials"}
	var path string
	bearer := &cobra.Command{
		Use:   "bearer",
		Short: "Print a token as an HTTP bearer credential",
		Long: `Prints a capability token in the form the server accepts in an Authorization
header, for an agent or CI job that talks to the server directly:

  git -c http.extraHeader="Authorization: Bearer $(mei token bearer)" push meiosis main`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				root, err := repoRoot(settings)
				if err != nil {
					return err
				}
				path = filepath.Join(root, ".agents", "meiosis-capability.json")
			}
			t, err := loadToken(path)
			if err != nil {
				return err
			}
			b, err := identity.Bearer(t)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), b)
			return err
		},
	}
	bearer.Flags().StringVar(&path, "token", "", "token file (default: <repo>/.agents/meiosis-capability.json)")
	token.AddCommand(bearer)
	return token
}

// newCredentialCommand implements a git credential helper that mints a fresh
// short-lived token, signed by the repository's human key, whenever git asks.
func newCredentialCommand(settings *Settings) *cobra.Command {
	var keyPath, principal string
	cmd := &cobra.Command{
		Use:    "credential [get|store|erase]",
		Short:  "Git credential helper: supplies the server with a fresh capability token",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && args[0] != "get" {
				return nil // store and erase: nothing to remember, tokens are minted on demand
			}
			_, _ = readCredentialRequest(cmd.InOrStdin())

			root, err := repoRoot(settings)
			if err != nil {
				return err
			}
			if keyPath == "" {
				keyPath = filepath.Join(root, ".meiosis", "human.private.key")
			}
			data, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read human key: %w", err)
			}
			keys, err := crypto.LoadEncodedKeyPair(string(data), "")
			if err != nil {
				return fmt.Errorf("load human key: %w", err)
			}
			if principal == "" {
				name, nameErr := defaultHumanName()
				if nameErr != nil {
					return nameErr
				}
				principal = "human:" + name
			}
			t, err := identity.Issue(identity.IssueParams{
				Principal: principal, IssuedBy: principal, Intent: specv1.CapabilityTokenAnyIntent,
				Scope:      specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce},
				Operations: []string{"git_fetch", "git_push"}, HolderKey: keys.PublicKey, TTL: credentialTTL,
			}, keys.PrivateKey)
			if err != nil {
				return err
			}
			b, err := identity.Bearer(t)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "username=mei\npassword=%s\n", b)
			return err
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "human signing key (default: <repo>/.meiosis/human.private.key)")
	cmd.Flags().StringVar(&principal, "principal", "", "principal the token is for (default: human:<username>)")
	return cmd
}

// readCredentialRequest reads the key=value lines git sends a credential helper.
func readCredentialRequest(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out, scanner.Err()
}

func newRemoteCommand(settings *Settings) *cobra.Command {
	remote := &cobra.Command{Use: "remote", Short: "Connect a git repository to a meiosis server"}
	var url string
	add := &cobra.Command{
		Use:   "add [name]",
		Short: "Add a git remote for this repository's meiosis server, with credentials handled for you",
		Long: `Adds a remote (default name: meiosis) pointing at the server and configures a
git credential helper for it that mints a short-lived capability token from the
repository's human key each time git asks. After this, plain git commands work:

  git push meiosis main
  git push -o intent=int_... meiosis main      # push under a declared intent
  git clone <url>`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := "meiosis"
			if len(args) == 1 {
				name = args[0]
			}
			root, err := repoRoot(settings)
			if err != nil {
				return err
			}
			if url == "" {
				url = "http://127.0.0.1:8484/" + server.SanitizeRepoName(filepath.Base(root)) + ".git"
			}
			self, err := os.Executable()
			if err != nil {
				return err
			}
			if resolved, evalErr := filepath.EvalSymlinks(self); evalErr == nil {
				self = resolved
			}
			base := url
			if i := strings.Index(strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://"), "/"); i >= 0 {
				prefix := len(url) - len(strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://"))
				base = url[:prefix+i]
			}
			helper := fmt.Sprintf("!%s credential --repo %s", shellArg(self), shellArg(root))
			for _, args := range [][]string{
				{"remote", "add", name, url},
				{"config", "credential." + base + ".helper", helper},
				{"config", "credential." + base + ".useHttpPath", "false"},
			} {
				c := exec.Command("git", append([]string{"-C", root}, args...)...)
				if out, runErr := c.CombinedOutput(); runErr != nil {
					return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), runErr, strings.TrimSpace(string(out)))
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "remote %q -> %s\ngit will ask `mei credential` for a token; try: git push %s main\n", name, url, name)
			return err
		},
	}
	add.Flags().StringVar(&url, "url", "", "server URL of the repository (default: http://127.0.0.1:8484/<this directory>.git)")
	remote.AddCommand(add)
	return remote
}

func shellArg(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func newRefsCommand(settings *Settings) *cobra.Command {
	var dbPath, ref string
	cmd := &cobra.Command{
		Use:   "refs",
		Short: "List ref updates and the world hash each produced",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			updates, err := store.ListRefUpdates(cmd.Context(), "", ref)
			if err != nil {
				return err
			}
			signer, err := loadIssuerKeyOrNil(settings)
			if err != nil {
				return err
			}
			type row struct {
				Update   specv1.RefUpdate `json:"update"`
				Verified *bool            `json:"signature_verified,omitempty"`
			}
			rows := make([]row, 0, len(updates))
			for _, u := range updates {
				r := row{Update: u}
				if signer != nil {
					ok, _ := crypto.Verify(u, u.Signature, signer)
					r.Verified = &ok
				}
				rows = append(rows, r)
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), rows)
			}
			if len(rows) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no ref updates recorded")
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "TIME\tREF\tCOMMIT\tWORLD\tPUSHED BY\tINTENT\tSCOPE\tSIGNATURE")
			for _, r := range rows {
				u := r.Update
				intent := shortID(u.Intent)
				if u.ImplicitIntent {
					intent += " (implicit)"
				}
				sig := "unchecked"
				if r.Verified != nil {
					sig = "verified"
					if !*r.Verified {
						sig = "FAILED"
					}
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d violation(s)\t%s\n", u.At.Format("15:04:05"), strings.TrimPrefix(u.Ref, "refs/heads/"),
					u.NewCommit[:12], u.World.String()[:12], u.PushedBy, intent, len(u.ScopeViolations), sig)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&ref, "ref", "", "only this ref, e.g. refs/heads/main")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

// loadIssuerKeyOrNil returns the repository's human public key, which is also
// what the server's records are signed with by default, or nil if absent.
func loadIssuerKeyOrNil(settings *Settings) ([]byte, error) {
	k, err := loadIssuerKey(settings, "")
	if err != nil || k == nil {
		return nil, err
	}
	return k, nil
}
