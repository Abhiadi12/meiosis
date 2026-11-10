package cli

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func repoRoot(settings *Settings) (string, error) {
	root := settings.Repo
	if root == "" {
		root = "."
	}
	return filepath.Abs(root)
}

func loadToken(path string) (specv1.CapabilityToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return specv1.CapabilityToken{}, fmt.Errorf("read token: %w", err)
	}
	return identity.Decode(data)
}

// loadIssuerKey reads the repository's trusted issuer (human) public key, if
// there is one.
func loadIssuerKey(settings *Settings, explicit string) (ed25519.PublicKey, error) {
	path := explicit
	if path == "" {
		root, err := repoRoot(settings)
		if err != nil {
			return nil, err
		}
		path = filepath.Join(root, ".meiosis", "human.public.key")
		if _, statErr := os.Stat(path); statErr != nil {
			return nil, nil //nolint:nilerr // no trust key on disk is not an error: the chain is then not verified here
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read issuer public key: %w", err)
	}
	return crypto.LoadEncodedPublicKey(string(data))
}

func newIntentDelegateCommand(settings *Settings) *cobra.Command {
	var (
		tokenPath, keyPath, to, holderKeyPath, generateKey, issuerPath, out, intentID string
		allow, deny, operations                                                       []string
		mode                                                                          string
		spendCeiling                                                                  int64
		ttl                                                                           time.Duration
	)
	cmd := &cobra.Command{
		Use:   "delegate",
		Short: "Delegate a strict subset of a capability token to a sub-agent",
		Long: `Issues a token for --to from the token you hold, signed with your key. It may hold
only a subset of the parent on every axis: paths, operations, spend ceiling and
lifetime can narrow but never widen, and widening is refused here. The delegated
token embeds its parent, so the chain back to the originating human travels with it.

Anything you leave out is inherited. --allow replaces the parent's allowed paths;
--deny is added to the parent's denies, which always carry over. The sub-agent
needs its own key: pass its public key with --holder-key, or let --generate-key
create a keypair and write the private key where you say.`,
		Example: "  mei intent delegate --token .agents/meiosis-capability.json --key .meiosis/agent.private.key \\\n" +
			"    --to agent:tests-1 --generate-key tests-1.key --allow 'src/auth/**' --operation attempt_write --spend-ceiling 500000 --out tests-1.token.json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tokenPath == "" || keyPath == "" || to == "" {
				return errors.New("--token, --key and --to are required")
			}
			if holderKeyPath != "" && generateKey != "" {
				return errors.New("give --holder-key or --generate-key, not both")
			}
			parent, err := loadToken(tokenPath)
			if err != nil {
				return err
			}
			keyData, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read key: %w", err)
			}
			delegator, err := crypto.LoadEncodedKeyPair(string(keyData), "")
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}

			// Refuse early to delegate from a token that would not verify: a
			// delegation from it would be useless.
			issuer, err := loadIssuerKey(settings, issuerPath)
			if err != nil {
				return err
			}
			if issuer != nil {
				if verr := identity.Verify(parent, issuer, nil, time.Now()); verr != nil {
					return fmt.Errorf("the token to delegate from does not verify: %w", verr)
				}
			}

			params := identity.DelegateParams{Principal: to, Intent: intentID, TTL: ttl}
			if cmd.Flags().Changed("allow") || cmd.Flags().Changed("deny") || cmd.Flags().Changed("mode") {
				scope := specv1.Scope{
					Allow: parent.Scope.Allow,
					Deny:  append(append([]string(nil), parent.Scope.Deny...), deny...),
					Mode:  parent.Scope.Mode,
				}
				if cmd.Flags().Changed("allow") {
					scope.Allow = allow
				}
				if cmd.Flags().Changed("mode") {
					scope.Mode = specv1.ScopeMode(mode)
				}
				params.Scope = &scope
			}
			if cmd.Flags().Changed("operation") {
				params.Operations = operations
			}
			if cmd.Flags().Changed("spend-ceiling") {
				params.SpendCeilingMicros = &spendCeiling
			}

			var (
				fresh  crypto.KeyPair
				genErr error
			)
			switch {
			case holderKeyPath != "":
				data, readErr := os.ReadFile(holderKeyPath)
				if readErr != nil {
					return fmt.Errorf("read holder key: %w", readErr)
				}
				if params.HolderKey, err = crypto.LoadEncodedPublicKey(string(data)); err != nil {
					return fmt.Errorf("load holder key: %w", err)
				}
			case generateKey != "":
				if fresh, genErr = crypto.GenerateKeyPair(); genErr != nil {
					return genErr
				}
				params.HolderKey = fresh.PublicKey
			}

			child, err := identity.Delegate(parent, params, delegator.PrivateKey)
			if err != nil {
				return fmt.Errorf("delegate: %w", err)
			}
			if generateKey != "" {
				// Written only once the delegation succeeded, so a refused one
				// leaves no stray key behind.
				if err = os.WriteFile(generateKey, []byte(fresh.PrivateKeyBase64()), 0o600); err != nil {
					return fmt.Errorf("write the sub-agent's key: %w", err)
				}
			}
			encoded, err := identity.Encode(child)
			if err != nil {
				return fmt.Errorf("encode token: %w", err)
			}
			if out == "" {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return err
			}
			if err = os.WriteFile(out, encoded, 0o600); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "delegated %s to %s (depth %d, expires %s); chain: %s\n", child.ID, to, child.Depth(),
				child.ExpiresAt.Format(time.RFC3339), chainLine(child))
			return err
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&tokenPath, "token", "", "the token to delegate from")
	flags.StringVar(&keyPath, "key", "", "private key of that token's holder")
	flags.StringVar(&to, "to", "", "the sub-agent principal, e.g. agent:tests-1")
	flags.StringVar(&holderKeyPath, "holder-key", "", "the sub-agent's public key file")
	flags.StringVar(&generateKey, "generate-key", "", "create a keypair for the sub-agent and write its private key here")
	flags.StringVar(&issuerPath, "issuer-pubkey", "", "trusted issuer public key to verify the parent against (default: <repo>/.meiosis/human.public.key if present)")
	flags.StringVar(&out, "out", "", "file to write the delegated token to (default: stdout)")
	flags.StringVar(&intentID, "intent", "", "bind the delegated token to one intent")
	flags.StringArrayVar(&allow, "allow", nil, "paths the sub-agent may touch (replaces the parent's; must lie within them)")
	flags.StringArrayVar(&deny, "deny", nil, "extra paths to deny, added to the parent's")
	flags.StringVar(&mode, "mode", string(specv1.ScopeModeEnforce), "scope mode")
	flags.StringArrayVar(&operations, "operation", nil, "tool the sub-agent may call (repeatable; must be among the parent's)")
	flags.Int64Var(&spendCeiling, "spend-ceiling", 0, "most the sub-agent may spend, in micro-units; counts against the parent's too")
	flags.DurationVar(&ttl, "ttl", 0, "lifetime (default: an hour, never beyond the parent's)")
	return cmd
}

func chainLine(token specv1.CapabilityToken) string {
	links := identity.Links(token)
	parts := make([]string, 0, len(links)+1)
	for _, l := range links {
		parts = append(parts, l.Principal)
	}
	parts = append(parts, identity.Origin(token))
	return strings.Join(parts, " <- ")
}

func newChainCommand(settings *Settings) *cobra.Command {
	var dbPath, issuerPath string
	cmd := &cobra.Command{
		Use:   "chain [id]",
		Short: "Show who authorised each write, back to the originating human",
		Long: `Lists the writes recorded for an intent, attempt or object (an ID or unique
prefix; with no argument, every write), each with the delegation chain it was
made under and whether that chain verifies against the repository's issuer key
as of the moment of the write.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			issuer, err := loadIssuerKey(settings, issuerPath)
			if err != nil {
				return err
			}

			ref := ""
			if len(args) == 1 {
				ref = args[0]
			}
			records, err := store.ListAuthority(cmd.Context(), "")
			if err != nil {
				return err
			}
			var shown []specv1.AuthorityRecord
			for _, r := range records {
				if ref == "" || hasPrefixAny(ref, r.Object, r.Attempt, r.Intent) {
					shown = append(shown, r)
				}
			}

			type entry struct {
				Record   specv1.AuthorityRecord `json:"record"`
				Origin   string                 `json:"origin"`
				Chain    []identity.ChainLink   `json:"chain"`
				Verified *bool                  `json:"verified,omitempty"`
				Problem  string                 `json:"problem,omitempty"`
			}
			entries := make([]entry, 0, len(shown))
			for _, r := range shown {
				e := entry{Record: r, Origin: identity.Origin(r.Token), Chain: identity.Links(r.Token)}
				if issuer != nil {
					ok := true
					if verr := identity.Verify(r.Token, issuer, nil, r.At); verr != nil {
						ok = false
						e.Problem = verr.Error()
					}
					e.Verified = &ok
				}
				entries = append(entries, e)
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), entries)
			}
			if len(entries) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no recorded writes")
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "TIME\tOP\tOBJECT\tPATH\tCHAIN\tCHECK")
			for _, e := range entries {
				check := "unchecked (no issuer key)"
				if e.Verified != nil {
					check = "verified"
					if !*e.Verified {
						check = "FAILED: " + e.Problem
					}
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Record.At.Format("15:04:05"), e.Record.Op, shortID(e.Record.Object), e.Record.Path, chainLine(e.Record.Token), check)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	cmd.Flags().StringVar(&issuerPath, "issuer-pubkey", "", "trusted issuer public key (default: <repo>/.meiosis/human.public.key if present)")
	return cmd
}

func hasPrefixAny(prefix string, values ...string) bool {
	for _, v := range values {
		if v != "" && strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}
