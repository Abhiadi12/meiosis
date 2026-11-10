package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage"
)

var (
	// ErrUnknownIntent is returned when a parent, dependency or target intent
	// does not exist.
	ErrUnknownIntent = errors.New("graph: unknown intent")
	// ErrCycle is returned when an intent would create a dependency cycle
	// (FR-3.7).
	ErrCycle = errors.New("graph: intent dependency cycle")
)

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// edges returns the intents an intent points at: its parent and dependencies.
func edges(i specv1.Intent) []string {
	out := append([]string(nil), i.DependsOn...)
	if i.Parent != "" {
		out = append(out, i.Parent)
	}
	return out
}

// checkLinks verifies that every parent and dependency of intent exists and
// that adding intent keeps the intent graph acyclic (FR-3.7).
//
// Intent IDs are content-derived and an intent can only reference intents that
// already exist, so a cycle cannot form among stored intents directly. It can
// form through supersession: a successor stands in for its predecessor, so a
// successor that depends (transitively) on the intent it replaces would depend
// on itself. supersedes names that predecessor. The walk also fails on any
// cycle already present in storage, which would indicate corruption.
func checkLinks(ctx context.Context, tx storage.Tx, intent specv1.Intent, supersedes string) error {
	if intent.ID != "" {
		for _, ref := range edges(intent) {
			if ref == intent.ID {
				return fmt.Errorf("%w: %s refers to itself", ErrCycle, intent.ID)
			}
		}
	}

	const (
		inProgress = 1
		done       = 2
	)
	state := map[string]int{}
	var visit func(id string, path []string) error
	visit = func(id string, path []string) error {
		if id == supersedes {
			return fmt.Errorf("%w: %s depends on %s, which it supersedes (via %v)", ErrCycle, intent.ID, supersedes, path)
		}
		switch state[id] {
		case done:
			return nil
		case inProgress:
			return fmt.Errorf("%w: %v", ErrCycle, append(path, id))
		}
		state[id] = inProgress
		node, err := loadIntent(ctx, tx, id)
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrUnknownIntent, id)
		}
		if err != nil {
			return err
		}
		for _, next := range edges(node) {
			if visitErr := visit(next, append(path, id)); visitErr != nil {
				return visitErr
			}
		}
		state[id] = done
		return nil
	}

	for _, ref := range edges(intent) {
		if visitErr := visit(ref, nil); visitErr != nil {
			return visitErr
		}
	}
	return nil
}
