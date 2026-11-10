package graph

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

var (
	// ErrAlreadySuperseded is returned when superseding an intent that already
	// has a successor.
	ErrAlreadySuperseded = errors.New("graph: intent is already superseded")
	// ErrNotSupersedable is returned when superseding an intent whose lifecycle
	// has ended.
	ErrNotSupersedable = errors.New("graph: intent can no longer be superseded")
)

// IntentView is an intent together with its current lifecycle state. The
// embedded Intent is the immutable, signed record exactly as declared;
// CurrentStatus and SupersededBy come from its separate state record.
type IntentView struct {
	specv1.Intent
	CurrentStatus specv1.IntentStatus `json:"current_status"`
	SupersededBy  string              `json:"superseded_by,omitempty"`
}

// Open reports whether new attempts may be opened on the intent.
func (v IntentView) Open() bool {
	return v.SupersededBy == "" && (v.CurrentStatus == specv1.IntentStatusOpen || v.CurrentStatus == specv1.IntentStatusAttempting)
}

func loadIntentView(ctx context.Context, g getter, id string) (IntentView, error) {
	data, err := g.Get(ctx, storage.KindIntent, id)
	if err != nil {
		return IntentView{}, fmt.Errorf("graph: load intent %q: %w", id, err)
	}
	var intent specv1.Intent
	if err = json.Unmarshal(data, &intent); err != nil {
		return IntentView{}, fmt.Errorf("graph: decode intent %q: %w", id, err)
	}
	view := IntentView{Intent: intent, CurrentStatus: intent.Status}

	stateData, err := g.Get(ctx, storage.KindIntentState, id)
	switch {
	case err == nil:
		var state specv1.IntentState
		if err = json.Unmarshal(stateData, &state); err != nil {
			return IntentView{}, fmt.Errorf("graph: decode intent state %q: %w", id, err)
		}
		view.CurrentStatus = state.Status
		view.SupersededBy = state.SupersededBy
	case !errors.Is(err, storage.ErrNotFound):
		return IntentView{}, err
	}
	return view, nil
}

func writeIntentState(ctx context.Context, tx storage.Tx, state specv1.IntentState, key ed25519.PrivateKey) error {
	state.UpdatedAt = time.Now().UTC()
	signature, err := crypto.Sign(state, key)
	if err != nil {
		return fmt.Errorf("graph: sign intent state: %w", err)
	}
	state.Signature = signature
	if err = state.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	encoded, err := specv1.Canonicalize(state)
	if err != nil {
		return fmt.Errorf("graph: encode intent state: %w", err)
	}
	return tx.Put(ctx, storage.KindIntentState, state.Intent, encoded)
}

// GetIntentView returns an intent with its current lifecycle state.
func (s *Store) GetIntentView(ctx context.Context, id string) (IntentView, error) {
	return loadIntentView(ctx, s.backend, id)
}

// ListIntentViews returns intents oldest first. Superseded intents are
// omitted unless includeSuperseded is set.
func (s *Store) ListIntentViews(ctx context.Context, includeSuperseded bool) ([]IntentView, error) {
	records, err := s.backend.List(ctx, storage.KindIntent)
	if err != nil {
		return nil, fmt.Errorf("graph: list intents: %w", err)
	}
	states, err := s.backend.List(ctx, storage.KindIntentState)
	if err != nil {
		return nil, fmt.Errorf("graph: list intent states: %w", err)
	}
	views := make([]IntentView, 0, len(records))
	for id, data := range records {
		var intent specv1.Intent
		if err = json.Unmarshal(data, &intent); err != nil {
			return nil, fmt.Errorf("graph: decode intent %q: %w", id, err)
		}
		view := IntentView{Intent: intent, CurrentStatus: intent.Status}
		if raw, ok := states[id]; ok {
			var state specv1.IntentState
			if err = json.Unmarshal(raw, &state); err != nil {
				return nil, fmt.Errorf("graph: decode intent state %q: %w", id, err)
			}
			view.CurrentStatus, view.SupersededBy = state.Status, state.SupersededBy
		}
		if view.SupersededBy != "" && !includeSuperseded {
			continue
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if !views[i].CreatedAt.Equal(views[j].CreatedAt) {
			return views[i].CreatedAt.Before(views[j].CreatedAt)
		}
		return views[i].ID < views[j].ID
	})
	return views, nil
}

// SupersedeIntent replaces an intent with a successor (FR-3.2). Intents are
// immutable, so the predecessor is left exactly as it was and only its state
// record changes: it gains a SupersededBy pointer and accepts no new attempts.
// The successor is a new, independently signed intent.
func (s *Store) SupersedeIntent(ctx context.Context, predecessorID string, p CreateIntentParams, signerKey ed25519.PrivateKey) (specv1.Intent, error) {
	var successor specv1.Intent
	err := s.backend.Transaction(ctx, func(tx storage.Tx) error {
		predecessor, err := loadIntentView(ctx, tx, predecessorID)
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrUnknownIntent, predecessorID)
		}
		if err != nil {
			return err
		}
		if predecessor.SupersededBy != "" {
			return fmt.Errorf("%w: %s is superseded by %s", ErrAlreadySuperseded, predecessorID, predecessor.SupersededBy)
		}
		if predecessor.CurrentStatus == specv1.IntentStatusMerged {
			return fmt.Errorf("%w: %s is merged", ErrNotSupersedable, predecessorID)
		}

		if successor, err = createIntentTx(ctx, tx, p, signerKey, predecessorID); err != nil {
			return err
		}
		return writeIntentState(ctx, tx, specv1.IntentState{
			Intent:       predecessorID,
			Status:       predecessor.CurrentStatus,
			SupersededBy: successor.ID,
			UpdatedBy:    p.CreatedBy,
		}, signerKey)
	})
	if err != nil {
		return specv1.Intent{}, err
	}
	return successor, nil
}

// markAttempting moves an open intent to "attempting" when its first attempt
// is opened. It is a no-op for an intent already past "open".
func markAttempting(ctx context.Context, tx storage.Tx, view IntentView, by string, key ed25519.PrivateKey) error {
	if view.CurrentStatus != specv1.IntentStatusOpen {
		return nil
	}
	return writeIntentState(ctx, tx, specv1.IntentState{
		Intent: view.ID, Status: specv1.IntentStatusAttempting, SupersededBy: view.SupersededBy, UpdatedBy: by,
	}, key)
}

// ---- auto-derivation (FR-3.8) -------------------------------------------------

// DeriveIntentParams describes the task an agent was given.
type DeriveIntentParams struct {
	Repo      string
	Task      string
	Scope     specv1.Scope // the authority the agent already holds
	CreatedBy string
}

const maxDerivedTitle = 80

// DeriveIntent synthesises an intent from an agent's task description, so the
// agent never has to author one (FR-3.8, RK-1). The title is the task's first
// line, the goal the full task, and the scope the authority the agent already
// holds. Deriving the same task again for the same agent, repo and scope
// returns the existing open intent rather than minting a duplicate; created
// reports whether a new intent was made.
func (s *Store) DeriveIntent(ctx context.Context, p DeriveIntentParams, signerKey ed25519.PrivateKey) (intent specv1.Intent, created bool, err error) {
	task := strings.TrimSpace(p.Task)
	if task == "" {
		return specv1.Intent{}, false, fmt.Errorf("%w: task must not be empty", ErrInvalidParams)
	}
	title := deriveTitle(task)

	err = s.backend.Transaction(ctx, func(tx storage.Tx) error {
		records, listErr := tx.List(ctx, storage.KindIntent)
		if listErr != nil {
			return listErr
		}
		var existing []IntentView
		for id := range records {
			view, vErr := loadIntentView(ctx, tx, id)
			if vErr != nil {
				return vErr
			}
			if view.Open() && view.Repo == p.Repo && view.Goal == task && view.CreatedBy == p.CreatedBy && reflect.DeepEqual(view.Scope, p.Scope) {
				existing = append(existing, view)
			}
		}
		if len(existing) > 0 {
			sort.Slice(existing, func(i, j int) bool { return existing[i].CreatedAt.After(existing[j].CreatedAt) })
			intent = existing[0].Intent
			return nil
		}

		intent, err = createIntentTx(ctx, tx, CreateIntentParams{
			Repo:       p.Repo,
			Title:      title,
			Goal:       task,
			Acceptance: []specv1.Criterion{{Text: "The task is complete as described: " + title}},
			Scope:      p.Scope,
			CreatedBy:  p.CreatedBy,
		}, signerKey, "")
		created = err == nil
		return err
	})
	if err != nil {
		return specv1.Intent{}, false, err
	}
	return intent, created, nil
}

// deriveTitle returns the first non-empty line of task, whitespace-collapsed
// and truncated to maxDerivedTitle characters.
func deriveTitle(task string) string {
	first := task
	if i := strings.IndexAny(task, "\r\n"); i >= 0 {
		first = task[:i]
	}
	first = strings.Join(strings.Fields(first), " ")
	if utf8.RuneCountInString(first) > maxDerivedTitle {
		runes := []rune(first)
		first = strings.TrimSpace(string(runes[:maxDerivedTitle-1])) + "…"
	}
	return first
}
