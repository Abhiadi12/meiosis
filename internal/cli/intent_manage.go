package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/graph"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// resolveIntent finds the intent whose ID equals, or uniquely starts with, ref.
func resolveIntent(views []graph.IntentView, ref string) (graph.IntentView, error) {
	var matches []graph.IntentView
	for _, v := range views {
		if v.ID == ref {
			return v, nil
		}
		if strings.HasPrefix(v.ID, ref) {
			matches = append(matches, v)
		}
	}
	switch len(matches) {
	case 0:
		return graph.IntentView{}, fmt.Errorf("no intent matches %q", ref)
	case 1:
		return matches[0], nil
	default:
		return graph.IntentView{}, fmt.Errorf("%q is ambiguous: it matches %d intents", ref, len(matches))
	}
}

func newIntentListCommand(settings *Settings) *cobra.Command {
	var (
		all    bool
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List intents with their current status, oldest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			views, err := store.ListIntentViews(context.Background(), all)
			if err != nil {
				return err
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), views)
			}
			if len(views) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no intents")
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "INTENT\tSTATUS\tMODE\tCREATED BY\tTITLE")
			for _, v := range views {
				status := string(v.CurrentStatus)
				if v.SupersededBy != "" {
					status += " (superseded)"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", shortID(v.ID), status, v.Scope.Mode, v.CreatedBy, v.Title)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include superseded intents")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

func newIntentShowCommand(settings *Settings) *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "show <intent>",
		Short: "Show an intent: scope, links, pinned context (re-verified) and its attempts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			ctx := context.Background()
			views, err := store.ListIntentViews(ctx, true)
			if err != nil {
				return err
			}
			view, err := resolveIntent(views, args[0])
			if err != nil {
				return err
			}
			attempts, err := store.ListAttempts(ctx, view.ID)
			if err != nil {
				return err
			}
			pins := graph.VerifyPins(settings.Repo, view.ContextPins)

			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{"intent": view, "pins": pins, "attempts": attempts})
			}
			return renderIntent(cmd.OutOrStdout(), view, pins, attempts)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

func renderIntent(w io.Writer, v graph.IntentView, pins []graph.PinCheck, attempts []specv1.Attempt) error {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("intent   %s\n", v.ID)
	p("title    %s\n", v.Title)
	p("goal     %s\n", v.Goal)
	status := string(v.CurrentStatus)
	if v.SupersededBy != "" {
		status += ", superseded by " + v.SupersededBy
	}
	p("status   %s\n", status)
	p("by       %s at %s\n", v.CreatedBy, v.CreatedAt.Format("2006-01-02 15:04:05Z"))
	p("scope    allow %s (mode %s)%s\n", strings.Join(v.Scope.Allow, ", "), v.Scope.Mode, denyClause(v.Scope.Deny))
	if v.Parent != "" {
		p("parent   %s\n", v.Parent)
	}
	if len(v.DependsOn) > 0 {
		p("depends  %s\n", strings.Join(v.DependsOn, ", "))
	}
	p("accept   %d criterion(s):\n", len(v.Acceptance))
	for _, c := range v.Acceptance {
		p("  - %s\n", c.Text)
	}
	for _, g := range v.NonGoals {
		p("non-goal %s\n", g)
	}
	if len(pins) == 0 {
		p("context  no pinned documents\n")
	} else {
		p("context  %d pinned document(s):\n", len(pins))
		for _, c := range pins {
			note := c.Status
			switch c.Status {
			case graph.PinChanged:
				note = "CHANGED since it was pinned: dependent attempts will go stale"
			case graph.PinMissing:
				note = "MISSING: dependent attempts will go stale"
			case graph.PinUnchecked:
				note = "not a local file, cannot be re-checked here"
			}
			p("  - %s [%s]: %s\n", c.Ref, c.Kind, note)
		}
	}
	p("attempts %d\n", len(attempts))
	for _, a := range attempts {
		p("  - %s by %s (%s)\n", shortID(a.ID), a.Author, a.Status)
	}
	return nil
}

func newIntentSupersedeCommand(settings *Settings) *cobra.Command {
	f := &intentFlags{}
	cmd := &cobra.Command{
		Use:   "supersede <intent> <title>",
		Short: "Replace an intent with a successor; fields you don't pass are inherited",
		Long: `Intents are immutable, so changing one means declaring a successor. The old
intent is left exactly as it was, records its successor, and accepts no new
attempts. Any field you do not pass is copied from the old intent.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := openHuman(settings, f)
			if err != nil {
				return err
			}
			defer h.close()
			old, err := resolveFor(h, args[0])
			if err != nil {
				return err
			}
			params, err := f.successorParams(cmd, h, old, args[1])
			if err != nil {
				return err
			}
			successor, err := h.store.SupersedeIntent(context.Background(), old.ID, params, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("supersede intent: %w", err)
			}
			return renderDeclared(cmd, settings, "declared (supersedes "+shortID(old.ID)+")", successor)
		},
	}
	f.register(cmd)
	return cmd
}

func newIntentPinCommand(settings *Settings) *cobra.Command {
	f := &intentFlags{}
	var kind string
	cmd := &cobra.Command{
		Use:   "pin <intent> <file>",
		Short: "Pin a document the author consumed, by recording its content digest",
		Long: `Records the BLAKE3 digest of <file> against an intent. Intents are immutable,
so this declares a successor that carries the new pin and supersedes the old
intent; everything else is inherited. If the file later changes, "mei intent
show" reports the pin as changed.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := openHuman(settings, f)
			if err != nil {
				return err
			}
			defer h.close()
			old, err := resolveFor(h, args[0])
			if err != nil {
				return err
			}
			pin, err := pinFile(h.root, args[1], specv1.ContextPinKind(kind))
			if err != nil {
				return err
			}
			params := inheritParams(old, h.name)
			replaced := false
			for i, existing := range params.ContextPins {
				if existing.Ref == pin.Ref {
					params.ContextPins[i], replaced = pin, true
				}
			}
			if !replaced {
				params.ContextPins = append(params.ContextPins, pin)
			}
			successor, err := h.store.SupersedeIntent(context.Background(), old.ID, params, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("pin: %w", err)
			}
			return renderDeclared(cmd, settings, "declared with "+pin.Ref+" pinned (supersedes "+shortID(old.ID)+")", successor)
		},
	}
	cmd.Flags().StringVar(&kind, "kind", string(specv1.ContextPinKindSpec), "kind of the document: spec, adr, issue, design or convention")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "path to the human signing key (default: <repo>/.meiosis/human.private.key)")
	cmd.Flags().StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	cmd.Flags().StringVar(&f.createdBy, "created-by", "", "declaring principal (default: human:<username>)")
	return cmd
}

func resolveFor(h *humanContext, ref string) (graph.IntentView, error) {
	views, err := h.store.ListIntentViews(context.Background(), true)
	if err != nil {
		return graph.IntentView{}, err
	}
	return resolveIntent(views, ref)
}

// inheritParams copies every field of an existing intent into creation
// parameters, for a successor that changes only some of them.
func inheritParams(old graph.IntentView, createdBy string) graph.CreateIntentParams {
	return graph.CreateIntentParams{
		Repo: old.Repo, Title: old.Title, Goal: old.Goal, Acceptance: old.Acceptance, NonGoals: old.NonGoals,
		Scope:       specv1.Scope{Allow: old.Scope.Allow, Deny: old.Scope.Deny, Mode: old.Scope.Mode},
		ContextPins: append([]specv1.ContextPin(nil), old.ContextPins...),
		Parent:      old.Parent, DependsOn: old.DependsOn, CreatedBy: createdBy,
	}
}

// successorParams starts from the old intent and overrides only the fields
// whose flags were passed.
func (f *intentFlags) successorParams(cmd *cobra.Command, h *humanContext, old graph.IntentView, title string) (graph.CreateIntentParams, error) {
	params := inheritParams(old, h.name)
	params.Title = title
	changed := cmd.Flags().Changed
	if changed("goal") {
		params.Goal = f.goal
	}
	if changed("acceptance") {
		params.Acceptance = nil
		for _, text := range f.acceptance {
			params.Acceptance = append(params.Acceptance, specv1.Criterion{Text: text})
		}
	}
	if changed("files") || changed("deny") || changed("mode") {
		if changed("files") {
			params.Scope.Allow = f.files
		}
		if changed("deny") {
			params.Scope.Deny = f.deny
		}
		if changed("mode") {
			params.Scope.Mode = specv1.ScopeMode(f.mode)
		}
	}
	if changed("non-goal") {
		params.NonGoals = f.nonGoals
	}
	if changed("parent") {
		params.Parent = f.parent
	}
	if changed("depends-on") {
		params.DependsOn = f.dependsOn
	}
	if changed("pin") {
		params.ContextPins = nil
		for _, ref := range f.pins {
			pin, err := pinFile(h.root, ref, specv1.ContextPinKind(f.pinKind))
			if err != nil {
				return graph.CreateIntentParams{}, err
			}
			params.ContextPins = append(params.ContextPins, pin)
		}
	}
	return params, nil
}
