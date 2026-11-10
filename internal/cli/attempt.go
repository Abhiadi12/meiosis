package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/graph"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// openGraph opens the repository's store for reading and writing graph
// objects. dbPath defaults to <repo>/.meiosis/meiosisd.db, the same database
// the meiosisd daemon serves. It refuses to create a database implicitly: a
// missing one means the repository was never initialised.
func openGraph(settings *Settings, dbPath string) (*graph.Store, func(), error) {
	if dbPath == "" {
		root := settings.Repo
		if root == "" {
			root = "."
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve repo path: %w", err)
		}
		dbPath = filepath.Join(absRoot, ".meiosis", "meiosisd.db")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, fmt.Errorf("no meiosis store at %s: %w (run `mei init`, then let an agent or `mei intent declare` create some data)", dbPath, err)
	}
	backend, err := sqlite.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open store %s: %w", dbPath, err)
	}
	store, err := graph.New(backend)
	if err != nil {
		_ = backend.Close()
		return nil, nil, err
	}
	return store, func() { _ = backend.Close() }, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func shortID(id string) string {
	if len(id) > 16 {
		return id[:16] + "…"
	}
	return id
}

func shortWorld(w specv1.WorldHash) string { return w.String()[:12] }

// resolveAttempt finds the attempt whose ID equals, or uniquely starts with,
// ref.
func resolveAttempt(attempts []specv1.Attempt, ref string) (specv1.Attempt, error) {
	var matches []specv1.Attempt
	for _, a := range attempts {
		if a.ID == ref {
			return a, nil
		}
		if strings.HasPrefix(a.ID, ref) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return specv1.Attempt{}, fmt.Errorf("no attempt matches %q", ref)
	case 1:
		return matches[0], nil
	default:
		return specv1.Attempt{}, fmt.Errorf("%q is ambiguous: it matches %d attempts", ref, len(matches))
	}
}

func newAttemptCommand(settings *Settings) *cobra.Command {
	attempt := &cobra.Command{
		Use:   "attempt",
		Short: "Inspect attempts: an agent's implementation of an intent",
	}
	attempt.AddCommand(newAttemptListCommand(settings), newAttemptShowCommand(settings))
	return attempt
}

func newAttemptListCommand(settings *Settings) *cobra.Command {
	var (
		intentID string
		dbPath   string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List attempts, oldest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			attempts, err := store.ListAttempts(context.Background(), intentID)
			if err != nil {
				return err
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), attempts)
			}
			if len(attempts) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no attempts")
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ATTEMPT\tSTATUS\tAUTHOR\tINTENT\tWORLD\tVIOLATIONS")
			for _, a := range attempts {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", shortID(a.ID), a.Status, a.Author, shortID(a.Intent), shortWorld(a.World), len(a.ScopeViolations))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&intentID, "intent", "", "only attempts on this intent")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

func newAttemptShowCommand(settings *Settings) *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "show <attempt>",
		Short: "Show an attempt: scope violations, provenance, workspace and evidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			ctx := context.Background()
			attempts, err := store.ListAttempts(ctx, "")
			if err != nil {
				return err
			}
			attempt, err := resolveAttempt(attempts, args[0])
			if err != nil {
				return err
			}
			report, err := graph.BuildAttemptReport(ctx, store, attempt)
			if err != nil {
				return err
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), report)
			}
			return renderAttemptReport(cmd.OutOrStdout(), report)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

func renderAttemptReport(w io.Writer, r graph.AttemptReport) error {
	a := r.Attempt
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

	p("attempt  %s\n", a.ID)
	p("intent   %s\n", a.Intent)
	p("author   %s\n", a.Author)
	p("status   %s\n", a.Status)
	p("world    %s", a.World)
	if !r.Committed {
		p("  (not committed: still the base world)")
	}
	p("\n")

	if len(a.ScopeViolations) == 0 {
		p("scope    no violations\n")
	} else {
		p("scope    %d violation(s):\n", len(a.ScopeViolations))
		for _, v := range a.ScopeViolations {
			p("  - %s: %s\n", v.Path, v.Reason)
		}
	}

	if r.Attestation == nil {
		p("provenance  none (attempt not committed)\n")
	} else {
		at := r.Attestation
		p("provenance  agent %s, model %s %s, tools %s\n", at.Agent, at.Model, at.ModelVer, strings.Join(at.Tools, ", "))
		p("            prompt digest %s, tokens in/out %d/%d, cost %d micros\n", at.PromptHash[:16]+"…", at.TokensIn, at.TokensOut, at.CostMicros)
	}

	p("workspace    %d file(s)", len(r.Written))
	if len(r.Deleted) > 0 {
		p(", %d deletion(s)", len(r.Deleted))
	}
	p("\n")
	for _, f := range r.Written {
		p("  + %s\n", f)
	}
	for _, f := range r.Deleted {
		p("  - %s\n", f)
	}

	if len(r.Evidence) == 0 {
		p("evidence     none\n")
		return nil
	}
	p("evidence     %d record(s):\n", len(r.Evidence))
	for _, e := range r.Evidence {
		freshness := "fresh"
		switch {
		case e.SupersededBy != "":
			freshness = "SUPERSEDED by " + shortID(e.SupersededBy) + " (not counted)"
		case !e.Fresh:
			freshness = "STALE (bound to a different world, not counted)"
		}
		independence := "independent"
		if !e.Independent {
			independence = "NOT independent (produced by the author)"
		}
		p("  - %s %s by %s: %s, %s\n", e.Kind, e.Outcome, e.Producer, independence, freshness)
	}
	return nil
}

func newEvidenceCommand(settings *Settings) *cobra.Command {
	evidence := &cobra.Command{
		Use:   "evidence",
		Short: "Inspect evidence bound to world hashes",
	}
	var (
		attemptRef string
		dbPath     string
	)
	list := &cobra.Command{
		Use:   "list",
		Short: "List evidence records, oldest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			ctx := context.Background()
			attemptID := ""
			var attempts []specv1.Attempt
			if attempts, err = store.ListAttempts(ctx, ""); err != nil {
				return err
			}
			if attemptRef != "" {
				resolved, rErr := resolveAttempt(attempts, attemptRef)
				if rErr != nil {
					return rErr
				}
				attemptID = resolved.ID
			}
			records, err := store.ListEvidence(ctx, attemptID)
			if err != nil {
				return err
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), records)
			}
			if len(records) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no evidence")
				return err
			}
			current := map[string]specv1.WorldHash{}
			for _, a := range attempts {
				current[a.ID] = a.World
			}
			superseded := graph.SupersededBy(records)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "EVIDENCE\tATTEMPT\tKIND\tOUTCOME\tPRODUCER\tINDEPENDENT\tSTANDING")
			for _, e := range records {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\t%s\n", shortID(e.ID), shortID(e.Attempt), e.Kind, e.Outcome, e.Producer, e.Independent, evidenceStanding(e, current, superseded))
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&attemptRef, "attempt", "", "only evidence for this attempt (ID or unique prefix)")
	list.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	evidence.AddCommand(list, newEvidenceSubmitCommand(settings), newEvidenceKindCommand(settings))
	return evidence
}

// repoStatus is the summary printed by `mei status`.
type repoStatus struct {
	Repo     string         `json:"repo"`
	Intents  int            `json:"intents"`
	Attempts map[string]int `json:"attempts"`
	Evidence struct {
		Total          int `json:"total"`
		Counted        int `json:"counted"`
		Stale          int `json:"stale"`
		Superseded     int `json:"superseded"`
		NotIndependent int `json:"not_independent"`
	} `json:"evidence"`
	AttemptsWithViolations []string `json:"attempts_with_scope_violations"`
}

func newStatusCommand(settings *Settings) *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Summarise intents, attempts, scope violations and evidence",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			ctx := context.Background()

			intents, err := store.ListIntents(ctx)
			if err != nil {
				return err
			}
			attempts, err := store.ListAttempts(ctx, "")
			if err != nil {
				return err
			}
			evidence, err := store.ListEvidence(ctx, "")
			if err != nil {
				return err
			}

			status := repoStatus{Repo: settings.Repo, Intents: len(intents), Attempts: map[string]int{}, AttemptsWithViolations: []string{}}
			current := map[string]specv1.WorldHash{}
			for _, a := range attempts {
				status.Attempts[string(a.Status)]++
				current[a.ID] = a.World
				if len(a.ScopeViolations) > 0 {
					status.AttemptsWithViolations = append(status.AttemptsWithViolations, a.ID)
				}
			}
			status.Evidence.Total = len(evidence)
			superseded := graph.SupersededBy(evidence)
			for _, e := range evidence {
				switch evidenceStanding(e, current, superseded) {
				case "superseded":
					status.Evidence.Superseded++
				case "stale":
					status.Evidence.Stale++
				default:
					status.Evidence.Counted++
				}
				if !e.Independent {
					status.Evidence.NotIndependent++
				}
			}

			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), status)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "intents    %d\n", status.Intents)
			_, _ = fmt.Fprintf(out, "attempts   %d (open %d, merged %d, abandoned %d)\n", len(attempts),
				status.Attempts["open"], status.Attempts["merged"], status.Attempts["abandoned"])
			_, _ = fmt.Fprintf(out, "evidence   %d (counted %d, stale %d, superseded %d, not independent %d)\n",
				status.Evidence.Total, status.Evidence.Counted, status.Evidence.Stale, status.Evidence.Superseded, status.Evidence.NotIndependent)
			if len(status.AttemptsWithViolations) > 0 {
				_, _ = fmt.Fprintf(out, "scope violations recorded on %d attempt(s):\n", len(status.AttemptsWithViolations))
				for _, id := range status.AttemptsWithViolations {
					_, _ = fmt.Fprintf(out, "  %s\n", id)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}
