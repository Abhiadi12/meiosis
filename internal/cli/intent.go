package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// newIntentCommand builds the "intent" command tree: "declare", which signs
// and persists a new intent as the human operator, and "authorize", which
// issues signed capability tokens scoping an agent to that intent (FR-1.3).
func newIntentCommand(settings *Settings) *cobra.Command {
	intent := newActionCommand("intent", "Manage intents", settings)
	intent.AddCommand(newIntentDeclareCommand(settings))
	intent.AddCommand(newIntentAuthorizeCommand())
	intent.AddCommand(newIntentRevokeCommand(settings), newIntentDelegateCommand(settings))
	intent.AddCommand(newIntentListCommand(settings), newIntentShowCommand(settings), newIntentSupersedeCommand(settings), newIntentPinCommand(settings))
	return intent
}

// intentFlags are the fields that describe an intent, shared by declare and
// supersede.
type intentFlags struct {
	goal       string
	acceptance []string
	files      []string
	deny       []string
	mode       string
	createdBy  string
	keyPath    string
	dbPath     string
	parent     string
	dependsOn  []string
	pins       []string
	pinKind    string
	nonGoals   []string
}

func (f *intentFlags) register(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&f.goal, "goal", "", "the change's goal (default: the title)")
	flags.StringArrayVar(&f.acceptance, "acceptance", nil, "acceptance criterion (repeatable; default: the title)")
	flags.StringArrayVar(&f.files, "files", nil, "path/glob the intents lets agents touch (repeatable; default: **)")
	flags.StringArrayVar(&f.deny, "deny", nil, "path/glob agents may not touch even if allowed (repeatable)")
	flags.StringVar(&f.mode, "mode", string(specv1.ScopeModeEnforce), "scope mode: enforce or warn")
	flags.StringVar(&f.createdBy, "created-by", "", "declaring principal (default: human:<username>)")
	flags.StringVar(&f.keyPath, "key", "", "path to the human signing key (default: <repo>/.meiosis/human.private.key)")
	flags.StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	flags.StringVar(&f.parent, "parent", "", "parent intent ID")
	flags.StringArrayVar(&f.dependsOn, "depends-on", nil, "intent ID this intent depends on (repeatable)")
	flags.StringArrayVar(&f.pins, "pin", nil, "repo-relative file to pin as consumed context (repeatable); its digest is recorded")
	flags.StringVar(&f.pinKind, "pin-kind", string(specv1.ContextPinKindSpec), "kind of the pinned documents: spec, adr, issue, design or convention")
	flags.StringArrayVar(&f.nonGoals, "non-goal", nil, "an explicit non-goal (repeatable)")
}

// humanContext is the repository's store opened with its human signing key.
type humanContext struct {
	root  string
	store *graph.Store
	keys  crypto.KeyPair
	name  string
	close func()
}

func openHuman(settings *Settings, f *intentFlags) (*humanContext, error) {
	root := settings.Repo
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}
	keyPath := f.keyPath
	if keyPath == "" {
		keyPath = filepath.Join(absRoot, ".meiosis", "human.private.key")
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read human key %s: %w (run `mei init` to bootstrap the repository)", keyPath, err)
	}
	keys, err := crypto.LoadEncodedKeyPair(string(keyData), "")
	if err != nil {
		return nil, fmt.Errorf("load human key: %w", err)
	}
	dbPath := f.dbPath
	if dbPath == "" {
		dbPath = filepath.Join(absRoot, ".meiosis", "meiosisd.db")
	}
	backend, err := sqlite.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open store %s: %w", dbPath, err)
	}
	store, err := graph.New(backend)
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("open graph: %w", err)
	}
	name := f.createdBy
	if name == "" {
		human, nameErr := defaultHumanName()
		if nameErr != nil {
			_ = backend.Close()
			return nil, nameErr
		}
		name = "human:" + human
	}
	return &humanContext{root: absRoot, store: store, keys: keys, name: name, close: func() { _ = backend.Close() }}, nil
}

// pinFile pins the repo-relative file ref under root as consumed context.
func pinFile(root, ref string, kind specv1.ContextPinKind) (specv1.ContextPin, error) {
	clean := path.Clean(filepath.ToSlash(ref))
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
		return specv1.ContextPin{}, fmt.Errorf("pin %q: must be a path inside the repository", ref)
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(clean)))
	if err != nil {
		return specv1.ContextPin{}, fmt.Errorf("pin %q: %w", ref, err)
	}
	return graph.NewContextPin(clean, kind, content)
}

// params builds the intent parameters from the flags, defaulting as declare does.
func (f *intentFlags) params(h *humanContext, title string) (graph.CreateIntentParams, error) {
	goal := f.goal
	if goal == "" {
		goal = title
	}
	criteria := make([]specv1.Criterion, 0, len(f.acceptance))
	for _, text := range f.acceptance {
		criteria = append(criteria, specv1.Criterion{Text: text})
	}
	if len(criteria) == 0 {
		criteria = append(criteria, specv1.Criterion{Text: title})
	}
	allow := f.files
	if len(allow) == 0 {
		allow = []string{"**"}
	}
	var pins []specv1.ContextPin
	for _, ref := range f.pins {
		pin, err := pinFile(h.root, ref, specv1.ContextPinKind(f.pinKind))
		if err != nil {
			return graph.CreateIntentParams{}, err
		}
		pins = append(pins, pin)
	}
	return graph.CreateIntentParams{
		Repo: h.root, Title: title, Goal: goal, Acceptance: criteria, NonGoals: f.nonGoals,
		Scope:       specv1.Scope{Allow: allow, Deny: f.deny, Mode: specv1.ScopeMode(f.mode)},
		ContextPins: pins, Parent: f.parent, DependsOn: f.dependsOn, CreatedBy: h.name,
	}, nil
}

func renderDeclared(cmd *cobra.Command, settings *Settings, verb string, intent specv1.Intent) error {
	if settings.Format == "json" {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"id": intent.ID, "title": intent.Title, "goal": intent.Goal, "repo": intent.Repo,
			"scope": intent.Scope, "status": intent.Status, "context_pins": intent.ContextPins,
		})
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "intent %s %s and signed: %s\n  scope: allow %s (mode %s)%s\n",
		intent.ID, verb, intent.Title, strings.Join(intent.Scope.Allow, ", "), intent.Scope.Mode, denyClause(intent.Scope.Deny))
	return err
}

// newIntentDeclareCommand implements "mei intent declare <title>": it builds,
// signs and persists a new intent using the repository's human key
// (.meiosis/human.private.key) into the same SQLite store the meiosisd daemon
// serves, so intents declared on the CLI are immediately visible to agents.
func newIntentDeclareCommand(settings *Settings) *cobra.Command {
	f := &intentFlags{}
	cmd := &cobra.Command{
		Use:     "declare <title>",
		Aliases: []string{"new"},
		Short:   "Declare a new intent, signed by the repository human key",
		Args:    cobra.ExactArgs(1),
		Example: "  mei intent declare \"Refactor the Button component\" --files \"src/components/Button.tsx\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			title := args[0]
			if strings.TrimSpace(title) == "" {
				return errors.New("intent title must not be empty")
			}
			h, err := openHuman(settings, f)
			if err != nil {
				return err
			}
			defer h.close()
			params, err := f.params(h, title)
			if err != nil {
				return err
			}
			intent, err := h.store.CreateIntent(context.Background(), params, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("declare intent: %w", err)
			}
			return renderDeclared(cmd, settings, "declared", intent)
		},
	}
	f.register(cmd)
	return cmd
}

func denyClause(deny []string) string {
	if len(deny) == 0 {
		return ""
	}
	return "; deny " + strings.Join(deny, ", ")
}

// newIntentAuthorizeCommand implements "mei intent authorize": it signs a
// capability token with the issuer's Ed25519 key, granting principal
// time-bounded, path-scoped permission to act within intent (FR-1.3/FR-1.4).
// The issuer, not the holder, signs it, so a principal can never mint or
// widen its own authority (FR-1.5).
func newIntentAuthorizeCommand() *cobra.Command {
	var (
		principal     string
		intentID      string
		issuedBy      string
		issuerKeyPath string
		ttl           time.Duration
		mode          string
		out           string
		allow         []string
		deny          []string
		holderKeyPath string
		operations    []string
		spendCeiling  int64
	)

	cmd := &cobra.Command{
		Use:   "authorize",
		Short: "Issue a signed capability token scoping a principal's access to an intent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if principal == "" || intentID == "" || issuedBy == "" || issuerKeyPath == "" || len(allow) == 0 {
				return errors.New("--principal, --intent, --issuer, --issuer-key and at least one --allow are required")
			}

			keyData, err := os.ReadFile(issuerKeyPath)
			if err != nil {
				return fmt.Errorf("read issuer key: %w", err)
			}
			keys, err := crypto.LoadEncodedKeyPair(string(keyData), "")
			if err != nil {
				return fmt.Errorf("load issuer key: %w", err)
			}

			params := identity.IssueParams{
				Principal:  principal,
				Intent:     intentID,
				IssuedBy:   issuedBy,
				Scope:      specv1.Scope{Allow: allow, Deny: deny, Mode: specv1.ScopeMode(mode)},
				TTL:        ttl,
				Operations: operations,
			}
			if cmd.Flags().Changed("spend-ceiling") {
				params.SpendCeilingMicros = &spendCeiling
			}
			if holderKeyPath != "" {
				data, readErr := os.ReadFile(holderKeyPath)
				if readErr != nil {
					return fmt.Errorf("read holder key: %w", readErr)
				}
				holder, loadErr := crypto.LoadEncodedPublicKey(string(data))
				if loadErr != nil {
					return fmt.Errorf("load holder key: %w", loadErr)
				}
				params.HolderKey = holder
			}
			token, err := identity.Issue(params, keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("issue token: %w", err)
			}

			encoded, err := identity.Encode(token)
			if err != nil {
				return fmt.Errorf("encode token: %w", err)
			}
			if out == "" {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return err
			}
			return os.WriteFile(out, encoded, 0o600)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&principal, "principal", "", "principal the capability is granted to, e.g. agent:impl-3")
	flags.StringVar(&intentID, "intent", "", "intent ID the capability is scoped to")
	flags.StringVar(&issuedBy, "issuer", "", "principal granting the capability, e.g. human:lakin")
	flags.StringVar(&issuerKeyPath, "issuer-key", "", "path to the issuer's Ed25519 private key (base64 or PEM)")
	flags.DurationVar(&ttl, "ttl", identity.DefaultTTL, "how long the token remains valid")
	flags.StringVar(&mode, "mode", string(specv1.ScopeModeEnforce), "scope mode: enforce or warn")
	flags.StringVar(&out, "out", "", "file to write the signed token to (default: stdout)")
	flags.StringArrayVar(&allow, "allow", nil, "glob path the token may touch (repeatable)")
	flags.StringArrayVar(&deny, "deny", nil, "glob path the token may not touch, even if allowed (repeatable)")
	flags.StringVar(&holderKeyPath, "holder-key", "", "public key file of the holder; needed for the holder to delegate the token")
	flags.StringArrayVar(&operations, "operation", nil, "tool the token permits (repeatable; default: all)")
	flags.Int64Var(&spendCeiling, "spend-ceiling", 0, "most cost, in micro-units, that commits under this token may report (default: no ceiling)")

	return cmd
}

// newIntentRevokeCommand implements "mei intent revoke": it durably revokes a
// capability token in the store the daemon reads, so the token stops working
// on the daemon's next call, without restarting it.
func newIntentRevokeCommand(settings *Settings) *cobra.Command {
	var (
		tokenFile string
		dbPath    string
	)
	cmd := &cobra.Command{
		Use:     "revoke [token-id]",
		Short:   "Revoke a capability token so the daemon rejects it from now on",
		Args:    cobra.MaximumNArgs(1),
		Example: "  mei intent revoke cap_abc...\n  mei intent revoke --token .agents/meiosis-capability.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			var tokenID string
			switch {
			case len(args) == 1 && tokenFile == "":
				tokenID = args[0]
			case len(args) == 0 && tokenFile != "":
				data, err := os.ReadFile(tokenFile)
				if err != nil {
					return fmt.Errorf("read token: %w", err)
				}
				token, err := identity.Decode(data)
				if err != nil {
					return err
				}
				tokenID = token.ID
			default:
				return errors.New("give exactly one of a token id argument or --token <file>")
			}

			if dbPath == "" {
				root := settings.Repo
				if root == "" {
					root = "."
				}
				absRoot, err := filepath.Abs(root)
				if err != nil {
					return fmt.Errorf("resolve repo path: %w", err)
				}
				dbPath = filepath.Join(absRoot, ".meiosis", "meiosisd.db")
			}
			store, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store %s: %w", dbPath, err)
			}
			defer func() { _ = store.Close() }()

			if err = identity.NewStoreRevocationList(store).Revoke(context.Background(), tokenID); err != nil {
				return fmt.Errorf("revoke token: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", tokenID)
			return err
		},
	}
	cmd.Flags().StringVar(&tokenFile, "token", "", "path to a token file whose id to revoke")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}
