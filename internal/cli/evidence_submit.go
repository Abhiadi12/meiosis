package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/evidence"
	"github.com/mindfire-test/meiosis/internal/graph"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/spec"
)

func newEvidenceSubmitCommand(settings *Settings) *cobra.Command {
	var (
		f          intentFlags
		attemptRef string
		from       string
		format     string
		kind       string
		worldHex   string
		footprint  []string
		supersedes string
		minLine    float64
		payload    string
		outcome    string
	)
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Turn a test, lint, coverage or SBOM report into signed evidence for an attempt",
		Long: `Reads a report your tools already produced and records it as evidence bound to a
world hash. Nothing is executed. The outcome comes from the report.

To record a result no adapter reads (a human review, a custom kind), pass the payload
yourself with --kind, --outcome and --payload FILE instead of --from.

Formats: ` + formatList() + `. The format is detected from the content unless --report-format is given.
The evidence is bound to the attempt's current world unless --world is given.

Evidence is signed by the repository's human key and so counts as independent of
an agent's attempt. Use --key and --producer to sign as another principal, such
as a CI runner.

A coverage report is a measurement: without --min-line-coverage it is recorded as
inconclusive, so a pass is never implied without a stated bar.`,
		Example: "  mei evidence submit --attempt att_abc --from junit.xml\n" +
			"  go test -json ./... | mei evidence submit --attempt att_abc --from -\n" +
			"  mei evidence submit --attempt att_abc --from cover.xml --min-line-coverage 80",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw := payload != ""
			switch {
			case raw && (from != "" || format != ""):
				return fmt.Errorf("--payload cannot be combined with --from or --report-format")
			case raw && (kind == "" || outcome == ""):
				return fmt.Errorf("--payload needs --kind and --outcome: nothing reads the payload to work them out")
			case !raw && from == "":
				return fmt.Errorf("--from is required: a report file, or - for standard input (or --payload to supply the result yourself)")
			case !raw && outcome != "":
				return fmt.Errorf("--outcome is only for --payload; a report's outcome comes from the report")
			}
			source := from
			if raw {
				source = payload
			}
			reader := cmd.InOrStdin()
			if source != "-" {
				file, err := os.Open(source)
				if err != nil {
					return fmt.Errorf("open %s: %w", source, err)
				}
				defer func() { _ = file.Close() }()
				reader = file
			}
			report, err := evidence.ReadReport(reader)
			if err != nil {
				return err
			}

			opts := evidence.Options{Kind: specv1.EvidenceKind(kind)}
			if cmd.Flags().Changed("min-line-coverage") {
				opts.MinLineCoverage = &minLine
			}
			var fmtName evidence.Format
			if format != "" {
				if fmtName, err = evidence.ParseFormat(format); err != nil {
					return err
				}
			}

			h, err := openHuman(settings, &f)
			if err != nil {
				return err
			}
			defer h.close()
			ctx := context.Background()

			attempts, err := h.store.ListAttempts(ctx, "")
			if err != nil {
				return err
			}
			attempt, err := pickAttempt(attempts, attemptRef)
			if err != nil {
				return err
			}
			world := attempt.World
			if worldHex != "" {
				if world, err = specv1.ParseWorldHash(worldHex); err != nil {
					return fmt.Errorf("--world: %w", err)
				}
			}
			supersedesID := supersedes
			if supersedes != "" {
				records, listErr := h.store.ListEvidence(ctx, attempt.ID)
				if listErr != nil {
					return listErr
				}
				if supersedesID, err = resolveEvidence(records, supersedes); err != nil {
					return err
				}
			}

			if raw {
				record, subErr := h.store.SubmitEvidence(ctx, graph.SubmitEvidenceParams{
					Attempt: attempt.ID, Producer: h.name, World: world, Kind: specv1.EvidenceKind(kind),
					Outcome: specv1.EvidenceOutcome(outcome), Payload: report, Footprint: footprint, Supersedes: supersedesID,
				}, h.keys.PrivateKey)
				if subErr != nil {
					return subErr
				}
				return renderSubmitted(cmd, settings, record, evidence.Report{Format: "payload"}, world == attempt.World)
			}
			record, parsed, err := evidence.Ingest(ctx, h.store, evidence.IngestParams{
				Attempt: attempt.ID, Producer: h.name, World: world, Format: fmtName,
				Options: opts, Footprint: footprint, Supersedes: supersedesID,
			}, h.keys.PrivateKey, report)
			if err != nil {
				return err
			}
			return renderSubmitted(cmd, settings, record, parsed, world == attempt.World)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&attemptRef, "attempt", "", "attempt ID or unique prefix (default: the only open attempt)")
	flags.StringVar(&from, "from", "", "report file, or - for standard input")
	flags.StringVar(&format, "report-format", "", "report format: "+formatList()+" (default: detect)")
	flags.StringVar(&kind, "kind", "", "evidence kind. With --from only SARIF has a choice (static-analysis, security-scan, type-check); with --payload any built-in or registered kind")
	flags.StringVar(&payload, "payload", "", "JSON file (or - for stdin) holding the evidence payload; use with --kind and --outcome")
	flags.StringVar(&outcome, "outcome", "", "pass, fail or inconclusive (with --payload only)")
	flags.StringVar(&worldHex, "world", "", "world hash the report was produced against (default: the attempt's current world)")
	flags.StringArrayVar(&footprint, "footprint", nil, "path the evidence depends on (repeatable)")
	flags.StringVar(&supersedes, "supersedes", "", "ID or prefix of an earlier record of yours on this attempt that this one corrects")
	flags.Float64Var(&minLine, "min-line-coverage", 0, "coverage reports: percent of lines required to pass")
	flags.StringVar(&f.createdBy, "producer", "", "principal the evidence is signed as (default: human:<username>)")
	flags.StringVar(&f.keyPath, "key", "", "path to the signing key (default: <repo>/.meiosis/human.private.key)")
	flags.StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

func formatList() string {
	names := make([]string, 0, len(evidence.Formats()))
	for _, f := range evidence.Formats() {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

// pickAttempt resolves ref, or, when no ref is given, the single open attempt.
func pickAttempt(attempts []specv1.Attempt, ref string) (specv1.Attempt, error) {
	if ref != "" {
		return resolveAttempt(attempts, ref)
	}
	var open []specv1.Attempt
	for _, a := range attempts {
		if a.Status == specv1.AttemptStatusOpen {
			open = append(open, a)
		}
	}
	switch len(open) {
	case 0:
		return specv1.Attempt{}, fmt.Errorf("there is no open attempt to attach evidence to")
	case 1:
		return open[0], nil
	}
	ids := make([]string, 0, len(open))
	for _, a := range open {
		ids = append(ids, shortID(a.ID))
	}
	return specv1.Attempt{}, fmt.Errorf("%d attempts are open (%s); pass --attempt", len(open), strings.Join(ids, ", "))
}

// resolveEvidence finds the evidence ID that equals, or uniquely starts with, ref.
func resolveEvidence(records []specv1.Evidence, ref string) (string, error) {
	var matches []string
	for _, e := range records {
		if e.ID == ref {
			return e.ID, nil
		}
		if strings.HasPrefix(e.ID, ref) {
			matches = append(matches, e.ID)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no evidence on this attempt matches %q", ref)
	case 1:
		return matches[0], nil
	}
	return "", fmt.Errorf("%q is ambiguous: it matches %d records", ref, len(matches))
}

func renderSubmitted(cmd *cobra.Command, settings *Settings, record specv1.Evidence, parsed evidence.Report, fresh bool) error {
	if settings.Format == "json" {
		return writeJSON(cmd.OutOrStdout(), map[string]any{"evidence": record, "format": parsed.Format, "fresh": fresh})
	}
	independence := "independent of the attempt's author"
	if !record.Independent {
		independence = "NOT independent: produced by the attempt's author"
	}
	extra := ""
	if record.Supersedes != "" {
		extra = ", supersedes " + shortID(record.Supersedes)
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "evidence %s recorded: %s %s (from %s) by %s, %s%s\n  bound to world %s\n",
		record.ID, record.Kind, record.Outcome, parsed.Format, record.Producer, independence, extra, shortWorld(record.World))
	return err
}

func newEvidenceKindCommand(settings *Settings) *cobra.Command {
	kind := &cobra.Command{
		Use:   "kind",
		Short: "List built-in evidence kinds and register custom ones",
	}

	var f intentFlags
	var schemaPath string
	register := &cobra.Command{
		Use:   "register <x-name>",
		Short: "Register a custom evidence kind with the JSON Schema its payloads must satisfy",
		Long: `Custom kinds are named x-NAME (lower-case letters, digits and hyphens) so they can
never collide with a kind the format adds later. Evidence of a custom kind is
accepted only once its kind is registered, and its payload is checked against
the schema. A registration is immutable: to change the schema, register a new
name such as x-NAME-v2.`,
		Example: "  mei evidence kind register x-license-check --schema license.schema.json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if schemaPath == "" {
				return fmt.Errorf("--schema is required")
			}
			schema, err := os.ReadFile(schemaPath)
			if err != nil {
				return fmt.Errorf("read schema: %w", err)
			}
			h, err := openHuman(settings, &f)
			if err != nil {
				return err
			}
			defer h.close()
			def, err := h.store.RegisterEvidenceKind(context.Background(), specv1.EvidenceKind(args[0]), schema, h.name, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("register kind: %w", err)
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), def)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "kind %s registered by %s\n", def.Kind, def.RegisteredBy)
			return err
		},
	}
	register.Flags().StringVar(&schemaPath, "schema", "", "file holding the JSON Schema for the kind's payload")
	register.Flags().StringVar(&f.createdBy, "created-by", "", "registering principal (default: human:<username>)")
	register.Flags().StringVar(&f.keyPath, "key", "", "path to the human signing key (default: <repo>/.meiosis/human.private.key)")
	register.Flags().StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")

	var dbPath string
	list := &cobra.Command{
		Use:   "list",
		Short: "List built-in kinds and registered custom kinds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := openGraph(settings, dbPath)
			if err != nil {
				return err
			}
			defer closeStore()
			custom, err := store.ListEvidenceKinds(context.Background())
			if err != nil {
				return err
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{"builtin": spec.EvidenceSchemaKinds(), "custom": custom})
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "KIND\tORIGIN\tREGISTERED BY")
			for _, k := range spec.EvidenceSchemaKinds() {
				_, _ = fmt.Fprintf(tw, "%s\tbuilt-in\t\n", k)
			}
			for _, d := range custom {
				_, _ = fmt.Fprintf(tw, "%s\tcustom\t%s\n", d.Kind, d.RegisteredBy)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")

	kind.AddCommand(register, list)
	return kind
}

// evidenceStanding classifies a record for listings: superseded takes
// precedence, then stale (bound to a world the attempt has moved past), else counted.
func evidenceStanding(e specv1.Evidence, current map[string]specv1.WorldHash, superseded map[string]string) string {
	switch {
	case superseded[e.ID] != "":
		return "superseded"
	case current[e.Attempt] != e.World:
		return "stale"
	}
	return "counted"
}
