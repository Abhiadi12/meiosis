package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/scope"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// workState remembers which attempt `mei work` is on for a repository.
type workState struct {
	Attempt string    `json:"attempt"`
	Intent  string    `json:"intent"`
	Started time.Time `json:"started"`
}

func workStatePath(root string) string { return filepath.Join(root, ".meiosis", "work.json") }

func loadWork(root string) (workState, error) {
	var w workState
	data, err := os.ReadFile(workStatePath(root))
	if errors.Is(err, os.ErrNotExist) {
		return w, fmt.Errorf("no attempt in progress: start one with `mei work start <intent>`")
	}
	if err != nil {
		return w, err
	}
	return w, json.Unmarshal(data, &w)
}

func saveWork(root string, w workState) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(workStatePath(root), data, 0o600)
}

// maxSubmitFile bounds one file `mei work submit` will take.
const maxSubmitFile = 32 << 20

func newWorkCommand(settings *Settings) *cobra.Command {
	work := &cobra.Command{
		Use:   "work",
		Short: "Do work on an intent yourself: start an attempt, check scope, submit your changes",
		Long: `The human's way into the attempt workflow that agents use over MCP. "start" opens
an attempt as you on an intent. "status" shows what you have changed in the git
working tree and whether each path is within the intent's scope. "submit" writes
those changes into the attempt (refusing the lot if any path is out of scope in
enforce mode), commits it with provenance, and prints the world hash.

The attempt's world holds the files you submitted, not the whole repository:
attempts are an overlay on an empty base in this release.`,
	}
	work.AddCommand(newWorkStartCommand(settings), newWorkStatusCommand(settings), newWorkSubmitCommand(settings), newWorkForkCommand(settings))
	return work
}

func newWorkStartCommand(settings *Settings) *cobra.Command {
	var f intentFlags
	var task string
	cmd := &cobra.Command{
		Use:   "start [intent]",
		Short: "Open an attempt on an intent (or derive an intent from --task)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 1) == (task != "") {
				return fmt.Errorf("give exactly one of an intent (ID or prefix) or --task")
			}
			h, err := openHuman(settings, &f)
			if err != nil {
				return err
			}
			defer h.close()
			ctx := context.Background()

			var intentID string
			if task != "" {
				intent, _, deriveErr := h.store.DeriveIntent(ctx, graph.DeriveIntentParams{
					Repo: h.root, Task: task, Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeWarn}, CreatedBy: h.name,
				}, h.keys.PrivateKey)
				if deriveErr != nil {
					return deriveErr
				}
				intentID = intent.ID
			} else {
				view, resolveErr := resolveFor(h, args[0])
				if resolveErr != nil {
					return resolveErr
				}
				intentID = view.ID
			}
			attempt, err := h.store.OpenAttempt(ctx, graph.OpenAttemptParams{Intent: intentID, Author: h.name}, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("open attempt: %w", err)
			}
			if err = saveWork(h.root, workState{Attempt: attempt.ID, Intent: intentID, Started: time.Now().UTC()}); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "attempt %s opened by %s on intent %s\nmake your changes, then: mei work status, mei work submit\n", attempt.ID, h.name, intentID)
			return err
		},
	}
	cmd.Flags().StringVar(&task, "task", "", "describe the task and let an intent be derived from it")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "human signing key (default: <repo>/.meiosis/human.private.key)")
	cmd.Flags().StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	cmd.Flags().StringVar(&f.createdBy, "as", "", "principal to work as (default: human:<username>)")
	return cmd
}

// treeChange is one path git reports as changed in the working tree.
type treeChange struct {
	Path    string
	Deleted bool
}

// workingTreeChanges lists the paths that differ from HEAD in the git
// repository at root: modified, added, untracked and deleted files. Ignored
// files are excluded, and so is meiosis's own directory.
func workingTreeChanges(ctx context.Context, root string) ([]treeChange, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git status: %w: %s (is %s a git repository?)", err, strings.TrimSpace(stderr.String()), root)
	}
	var changes []treeChange
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) < 4 {
			continue
		}
		xy, path := string(rec[:2]), string(rec[3:])
		if path == ".meiosis" || strings.HasPrefix(path, ".meiosis/") || strings.HasPrefix(path, ".git/") {
			continue
		}
		changes = append(changes, treeChange{Path: path, Deleted: strings.Contains(xy, "D")})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

// scopeVerdict is what the intent's scope says about one path.
type scopeVerdict struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted,omitempty"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func checkTree(intent graph.IntentView, changes []treeChange) []scopeVerdict {
	engine := scope.New(intent.Scope)
	out := make([]scopeVerdict, 0, len(changes))
	for _, c := range changes {
		d, err := engine.Evaluate(c.Path)
		v := scopeVerdict{Path: c.Path, Deleted: c.Deleted, Allowed: d.Allowed, Reason: d.Reason}
		if err != nil {
			v.Allowed, v.Reason = false, err.Error()
		}
		out = append(out, v)
	}
	return out
}

func newWorkStatusCommand(settings *Settings) *cobra.Command {
	var f intentFlags
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the attempt in progress and how your working tree changes sit against its intent's scope",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := openHuman(settings, &f)
			if err != nil {
				return err
			}
			defer h.close()
			state, err := loadWork(h.root)
			if err != nil {
				return err
			}
			ctx := context.Background()
			attempt, err := h.store.GetAttempt(ctx, state.Attempt)
			if err != nil {
				return err
			}
			intent, err := h.store.GetIntentView(ctx, attempt.Intent)
			if err != nil {
				return err
			}
			changes, err := workingTreeChanges(ctx, h.root)
			if err != nil {
				return err
			}
			verdicts := checkTree(intent, changes)
			ops, err := h.store.ListOperations(ctx, attempt.ID)
			if err != nil {
				return err
			}

			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{"attempt": attempt, "intent": intent.ID, "scope": intent.Scope, "working_tree": verdicts, "operations": len(ops)})
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "attempt %s (%s) on intent %s: %s\n", shortID(attempt.ID), attempt.Status, shortID(intent.ID), intent.Title)
			_, _ = fmt.Fprintf(out, "scope    allow %s (mode %s)%s\n", strings.Join(intent.Scope.Allow, ", "), intent.Scope.Mode, denyClause(intent.Scope.Deny))
			_, _ = fmt.Fprintf(out, "world    %s   %d operation(s) logged\n", shortWorld(attempt.World), len(ops))
			if len(verdicts) == 0 {
				_, err = fmt.Fprintln(out, "working tree: no changes to submit")
				return err
			}
			blocked := 0
			_, _ = fmt.Fprintf(out, "working tree: %d changed path(s)\n", len(verdicts))
			for _, v := range verdicts {
				mark, note := "  ok  ", ""
				if !v.Allowed {
					mark, note = " OUT  ", " — "+v.Reason
					if intent.Scope.Mode == specv1.ScopeModeEnforce {
						blocked++
					}
				}
				verb := "change"
				if v.Deleted {
					verb = "delete"
				}
				_, _ = fmt.Fprintf(out, "%s%s %s%s\n", mark, verb, v.Path, note)
			}
			if blocked > 0 {
				_, _ = fmt.Fprintf(out, "%d path(s) are outside the scope and `mei work submit` will refuse them (mode enforce)\n", blocked)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.keyPath, "key", "", "human signing key (default: <repo>/.meiosis/human.private.key)")
	cmd.Flags().StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	return cmd
}

func newWorkSubmitCommand(settings *Settings) *cobra.Command {
	var f intentFlags
	var model string
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Write your working-tree changes into the attempt and commit it with provenance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := openHuman(settings, &f)
			if err != nil {
				return err
			}
			defer h.close()
			state, err := loadWork(h.root)
			if err != nil {
				return err
			}
			ctx := context.Background()
			attempt, err := h.store.GetAttempt(ctx, state.Attempt)
			if err != nil {
				return err
			}
			if attempt.Author != h.name {
				return fmt.Errorf("attempt %s belongs to %s, not %s (use --as)", shortID(attempt.ID), attempt.Author, h.name)
			}
			intent, err := h.store.GetIntentView(ctx, attempt.Intent)
			if err != nil {
				return err
			}
			changes, err := workingTreeChanges(ctx, h.root)
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				return fmt.Errorf("nothing to submit: the working tree has no changes")
			}

			// All or nothing: refuse the whole submission if the scope forbids any path.
			if intent.Scope.Mode == specv1.ScopeModeEnforce {
				var bad []string
				for _, v := range checkTree(intent, changes) {
					if !v.Allowed {
						bad = append(bad, fmt.Sprintf("%s (%s)", v.Path, v.Reason))
					}
				}
				if len(bad) > 0 {
					return fmt.Errorf("nothing was submitted: %d path(s) are outside the scope of intent %s (mode enforce): %s", len(bad), intent.ID, strings.Join(bad, "; "))
				}
			}
			// Read everything before writing anything.
			type pending struct {
				path    string
				content []byte
				delete  bool
			}
			var todo []pending
			for _, c := range changes {
				if c.Deleted {
					todo = append(todo, pending{path: c.Path, delete: true})
					continue
				}
				content, readErr := readCapped(filepath.Join(h.root, filepath.FromSlash(c.Path)), maxSubmitFile)
				if readErr != nil {
					return fmt.Errorf("nothing was submitted: %s: %w", c.Path, readErr)
				}
				todo = append(todo, pending{path: c.Path, content: content})
			}
			for _, p := range todo {
				if _, err = h.store.WriteFile(ctx, graph.WriteParams{Attempt: attempt.ID, Author: h.name, Path: p.path, Content: p.content, Delete: p.delete}, h.keys.PrivateKey); err != nil {
					return fmt.Errorf("write %s: %w", p.path, err)
				}
			}
			res, err := h.store.CommitAttempt(ctx, graph.CommitParams{
				Attempt: attempt.ID, Author: h.name, Model: model, ModelVer: "n/a", Tools: []string{"mei work submit"},
			}, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("commit: %w", err)
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{"attempt": res.Attempt.ID, "world": res.Attempt.World.String(), "changed": res.Changed, "scope_violations": res.Attempt.ScopeViolations})
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "submitted %d path(s) to attempt %s\nworld %s\n", len(todo), shortID(attempt.ID), res.Attempt.World)
			deletions := 0
			for _, p := range todo {
				if p.delete {
					deletions++
				}
			}
			if deletions > 0 && attempt.BaseWorld == graph.EmptyWorld() {
				_, _ = fmt.Fprintf(out, "note: %d deletion(s) are logged, but this attempt has an empty base, so removing files it never held does not change its world\n", deletions)
			}
			_, err = fmt.Fprintf(out, "record evidence with: mei evidence submit --attempt %s --from <report>\n", shortID(attempt.ID))
			return err
		},
	}
	cmd.Flags().StringVar(&model, "model", "human", "what to record as the model that produced the work")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "human signing key (default: <repo>/.meiosis/human.private.key)")
	cmd.Flags().StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	cmd.Flags().StringVar(&f.createdBy, "as", "", "principal to work as (default: human:<username>)")
	return cmd
}

func readCapped(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%d bytes is over the %d byte limit", info.Size(), limit)
	}
	return io.ReadAll(file)
}

func newWorkForkCommand(settings *Settings) *cobra.Command {
	var f intentFlags
	var stay bool
	cmd := &cobra.Command{
		Use:   "fork [attempt]",
		Short: "Fork the attempt (default: the one in progress) into a new one of yours and switch to it",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			var source specv1.Attempt
			if len(args) == 1 {
				source, err = resolveAttempt(attempts, args[0])
			} else {
				var state workState
				if state, err = loadWork(h.root); err == nil {
					source, err = resolveAttempt(attempts, state.Attempt)
				}
			}
			if err != nil {
				return err
			}
			forked, err := h.store.ForkAttempt(ctx, graph.ForkParams{Source: source.ID, Author: h.name}, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("fork: %w", err)
			}
			if !stay {
				if err = saveWork(h.root, workState{Attempt: forked.ID, Intent: forked.Intent, Started: time.Now().UTC()}); err != nil {
					return err
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "forked %s into %s (same intent, same files so far)\n", shortID(source.ID), forked.ID)
			return err
		},
	}
	cmd.Flags().BoolVar(&stay, "stay", false, "keep working on the current attempt instead of switching to the fork")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "human signing key (default: <repo>/.meiosis/human.private.key)")
	cmd.Flags().StringVar(&f.dbPath, "db", "", "path to the store database (default: <repo>/.meiosis/meiosisd.db)")
	cmd.Flags().StringVar(&f.createdBy, "as", "", "principal to work as (default: human:<username>)")
	return cmd
}

// ---- mei op ----------------------------------------------------------------------

func newOpCommand(settings *Settings) *cobra.Command {
	op := &cobra.Command{
		Use:   "op",
		Short: "Inspect and undo the operations in an attempt's workspace",
	}
	resolve := func(h *humanContext, ref string) (specv1.Attempt, error) {
		attempts, err := h.store.ListAttempts(context.Background(), "")
		if err != nil {
			return specv1.Attempt{}, err
		}
		if ref == "" {
			state, stateErr := loadWork(h.root)
			if stateErr != nil {
				return specv1.Attempt{}, fmt.Errorf("%w (or pass --attempt)", stateErr)
			}
			ref = state.Attempt
		}
		return resolveAttempt(attempts, ref)
	}

	var logFlags intentFlags
	var logAttempt string
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "List the operations in a workspace, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := openHuman(settings, &logFlags)
			if err != nil {
				return err
			}
			defer h.close()
			attempt, err := resolve(h, logAttempt)
			if err != nil {
				return err
			}
			ops, err := h.store.ListOperations(context.Background(), attempt.ID)
			if err != nil {
				return err
			}
			if settings.Format == "json" {
				return writeJSON(cmd.OutOrStdout(), ops)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "OPERATION\tSEQ\tTIME\tKIND\tPATH / DETAIL\tBY")
			for _, o := range ops {
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", shortID(o.ID), o.Seq, o.At.Format("15:04:05"), o.Kind, opDetail(o), o.By)
			}
			return tw.Flush()
		},
	}
	logCmd.Flags().StringVar(&logAttempt, "attempt", "", "attempt (default: the one in progress)")
	logCmd.Flags().StringVar(&logFlags.keyPath, "key", "", "human signing key")
	logCmd.Flags().StringVar(&logFlags.dbPath, "db", "", "path to the store database")

	var undoFlags intentFlags
	var undoAttempt, undoOp string
	undoCmd := &cobra.Command{
		Use:   "undo",
		Short: "Undo the latest operation (or --op), keeping the history; undo again to redo",
		Long: `Undoing a write or delete puts the path back as it was. Undoing a commit restores
the exact world hash the attempt had before it, so evidence bound to that world
counts again. The undo is itself a logged operation: nothing is erased.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, err := openHuman(settings, &undoFlags)
			if err != nil {
				return err
			}
			defer h.close()
			attempt, err := resolve(h, undoAttempt)
			if err != nil {
				return err
			}
			target := undoOp
			if target != "" {
				ops, listErr := h.store.ListOperations(context.Background(), attempt.ID)
				if listErr != nil {
					return listErr
				}
				for _, o := range ops {
					if o.ID == target || strings.HasPrefix(o.ID, target) {
						target = o.ID
						break
					}
				}
			}
			reverted, err := h.store.RevertOperation(context.Background(), graph.RevertParams{Attempt: attempt.ID, Author: h.name, Operation: target}, h.keys.PrivateKey)
			if err != nil {
				return fmt.Errorf("undo: %w", err)
			}
			now, err := h.store.GetAttempt(context.Background(), attempt.ID)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "undid %s (%s); the attempt's world is %s\n", shortID(reverted.Reverts), opDetail(reverted), now.World)
			return err
		},
	}
	undoCmd.Flags().StringVar(&undoAttempt, "attempt", "", "attempt (default: the one in progress)")
	undoCmd.Flags().StringVar(&undoOp, "op", "", "operation to undo (ID or prefix; default: the latest)")
	undoCmd.Flags().StringVar(&undoFlags.keyPath, "key", "", "human signing key")
	undoCmd.Flags().StringVar(&undoFlags.dbPath, "db", "", "path to the store database")
	undoCmd.Flags().StringVar(&undoFlags.createdBy, "as", "", "principal to act as (default: human:<username>)")

	op.AddCommand(logCmd, undoCmd)
	return op
}

func opDetail(o specv1.Operation) string {
	switch o.Kind {
	case specv1.OperationWrite, specv1.OperationDelete:
		return o.Path
	case specv1.OperationCommit:
		return "world " + o.World.String()[:12]
	case specv1.OperationFork:
		return "from " + shortID(o.ForkedFrom)
	case specv1.OperationRevert:
		if o.Path != "" {
			return "undo of " + shortID(o.Reverts) + " on " + o.Path
		}
		return "undo of " + shortID(o.Reverts) + ", world " + o.World.String()[:12]
	}
	return ""
}
