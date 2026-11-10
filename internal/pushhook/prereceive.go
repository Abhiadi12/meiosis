package pushhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/scope"
	"github.com/mindfire-test/meiosis/internal/secrets"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/worlds"
)

// maxListed bounds how many offending paths a rejection spells out.
const maxListed = 15

// plan is what pre-receive worked out for one ref, left for post-receive so the
// tree is not hashed twice.
type plan struct {
	Ref        string                  `json:"ref"`
	Old        string                  `json:"old"`
	New        string                  `json:"new"`
	World      specv1.WorldHash        `json:"world"`
	BaseWorld  *specv1.WorldHash       `json:"base_world,omitempty"`
	Changed    int                     `json:"changed"`
	Violations []specv1.ScopeViolation `json:"violations,omitempty"`
	Findings   []specv1.SecretFinding  `json:"findings,omitempty"`
	Truncated  bool                    `json:"truncated,omitempty"`
	Intent     string                  `json:"intent,omitempty"`
	Pusher     string                  `json:"pusher"`
}

func (e Env) planPath(ref, newID string) string {
	name := strings.NewReplacer("/", "%2F", "\\", "%5C").Replace(ref) + "@" + newID + ".json"
	dir := e.GitDir
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "meiosis-pending", name)
}

func writePlan(path string, p plan) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readPlan(path string) (plan, error) {
	var p plan
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(data, &p)
}

// PreReceive decides whether a push may proceed. A nil return accepts it; a
// *RejectionError refuses it, and the reasons are also written to out (git shows
// them to the pusher as "remote: ..." lines).
func PreReceive(ctx context.Context, env Env, updates []Update, out io.Writer) error {
	s, err := open(env)
	if err != nil {
		return err
	}
	defer s.close()
	err = s.preReceive(ctx, updates, out)
	var rej *RejectionError
	if errors.As(err, &rej) {
		for _, r := range rej.Reasons {
			_, _ = fmt.Fprintf(out, "meiosis: REJECTED: %s\n", r)
		}
	}
	return err
}

func (s *session) preReceive(ctx context.Context, updates []Update, out io.Writer) error {
	now := time.Now()
	if err := s.authenticate(now); err != nil {
		return err
	}
	if err := s.resolveIntent(ctx); err != nil {
		return err
	}

	var reasons []string
	var plans []plan
	for _, u := range updates {
		if gitops.IsZero(u.New) {
			reasons = append(reasons, u.Ref+": deleting a ref is not allowed")
			continue
		}
		p, hard, err := s.examine(ctx, u)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", u.Ref, err))
			continue
		}
		reasons = append(reasons, hard...)
		plans = append(plans, p)
	}
	if len(reasons) > 0 {
		return &RejectionError{Reasons: reasons}
	}

	for _, p := range plans {
		if err := writePlan(s.env.planPath(p.Ref, p.New), p); err != nil {
			return fmt.Errorf("record the push plan: %w", err)
		}
		note := fmt.Sprintf("%s accepted as %s: %d path(s) changed", p.Ref, s.pusher, p.Changed)
		if s.intent != nil {
			note += ", under intent " + s.intent.ID
		} else {
			note += ", under an implicit intent (scope mode warn)"
		}
		if n := len(p.Findings); n > 0 {
			note += fmt.Sprintf("\nmeiosis: WARNING: %d possible credential(s) in this push (they were not blocked; secrets: %s): %s", n, s.env.Secrets, listRaw(describeAll(p.Findings)))
		}
		if p.Truncated {
			note += "\nmeiosis: WARNING: the diff was too large to scan for credentials in full"
		}
		if n := len(p.Violations); n > 0 {
			note += fmt.Sprintf("; %d path(s) outside the intent's scope were recorded as violations (mode warn)", n)
		}
		_, _ = fmt.Fprintf(out, "meiosis: %s\n", note)
	}
	return nil
}

// examine checks one ref update: every changed path against the token's scope
// and the intent's, and that the new tree can be hashed into a world. hard lists
// the reasons the push must be refused; the plan carries what is merely recorded.
func (s *session) examine(ctx context.Context, u Update) (plan, []string, error) {
	paths, err := s.repo.ChangedPaths(ctx, u.Ref, u.Old, u.New)
	if err != nil {
		return plan{}, nil, fmt.Errorf("cannot list the changed paths: %w", err)
	}

	var hard []string
	var violations []specv1.ScopeViolation
	var intentScope *scope.Engine
	if s.intent != nil {
		e := scope.New(s.intent.Scope)
		intentScope = &e
	}
	var tokenDenied, intentDenied, invalid []string
	for _, path := range paths {
		if addErr := worlds.NewHasher().Add(path, nil); addErr != nil {
			invalid = append(invalid, path)
			continue
		}
		if s.token != nil {
			ok, scopeErr := identity.TokenScopeAllows(*s.token, path)
			if scopeErr != nil {
				return plan{}, nil, fmt.Errorf("evaluate the token's scope for %q: %w", path, scopeErr)
			}
			if !ok {
				tokenDenied = append(tokenDenied, path)
				continue
			}
		}
		if intentScope != nil {
			d, evalErr := intentScope.Evaluate(path)
			if evalErr != nil {
				return plan{}, nil, fmt.Errorf("evaluate the intent's scope for %q: %w", path, evalErr)
			}
			if !d.Allowed {
				if s.intent.Scope.Mode == specv1.ScopeModeEnforce {
					intentDenied = append(intentDenied, fmt.Sprintf("%s (%s)", path, d.Reason))
				} else {
					violations = append(violations, specv1.ScopeViolation{Path: path, Reason: d.Reason})
				}
			}
		}
	}
	if len(invalid) > 0 {
		hard = append(hard, fmt.Sprintf("%s: %s cannot be recorded in a world (paths must be relative, use '/', and not contain '\\' or '..')", u.Ref, listPaths(invalid)))
	}
	if len(tokenDenied) > 0 {
		hard = append(hard, fmt.Sprintf("%s: %s outside the scope of your capability token (allow %v, deny %v)", u.Ref, listPathsVerb(tokenDenied), s.token.Scope.Allow, s.token.Scope.Deny))
	}
	if len(intentDenied) > 0 {
		hard = append(hard, fmt.Sprintf("%s: %s outside the scope of intent %s (mode enforce): %s", u.Ref, listPathsVerb(pathsOnly(intentDenied)), s.intent.ID, listRaw(intentDenied)))
	}
	findings, truncated, scanErr := s.scanSecrets(ctx, u, paths)
	if scanErr != nil {
		return plan{}, nil, fmt.Errorf("cannot scan for secrets: %w", scanErr)
	}
	if s.env.Secrets == secrets.ModeBlock {
		var blocking []string
		for _, f := range findings {
			if f.Confidence == string(secrets.High) {
				blocking = append(blocking, describe(f))
			}
		}
		if len(blocking) > 0 {
			hard = append(hard, fmt.Sprintf("%s: %d credential(s) found, and this repository blocks them (secrets: block): %s. Remove them and rotate the credentials: anything that has reached a remote must be treated as leaked", u.Ref, len(blocking), listRaw(blocking)))
		}
	}
	if len(hard) > 0 {
		return plan{}, hard, nil
	}

	world, _, err := s.repo.World(ctx, u.New)
	if err != nil {
		return plan{}, nil, fmt.Errorf("cannot hash the new tree into a world: %w", err)
	}
	p := plan{Ref: u.Ref, Old: u.Old, New: u.New, World: world, Changed: len(paths), Violations: violations, Pusher: s.pusher, Findings: findings, Truncated: truncated}
	if s.intent != nil {
		p.Intent = s.intent.ID
	}
	if !gitops.IsZero(u.Old) && u.Old != "" {
		base, err := s.baseWorld(ctx, u)
		if err != nil {
			return plan{}, nil, err
		}
		p.BaseWorld = &base
	}
	return p, nil, nil
}

// baseWorld is the world of the commit a ref is moving from: the one recorded
// when that commit arrived, else computed.
func (s *session) baseWorld(ctx context.Context, u Update) (specv1.WorldHash, error) {
	previous, err := s.store.ListRefUpdates(ctx, s.env.Repo, u.Ref)
	if err != nil {
		return specv1.WorldHash{}, err
	}
	for i := len(previous) - 1; i >= 0; i-- {
		if previous[i].NewCommit == u.Old {
			return previous[i].World, nil
		}
	}
	w, _, err := s.repo.World(ctx, u.Old)
	if err != nil {
		return specv1.WorldHash{}, fmt.Errorf("cannot hash the old tree into a world: %w", err)
	}
	return w, nil
}

func listPaths(paths []string) string {
	if len(paths) > maxListed {
		return fmt.Sprintf("%s and %d more path(s)", strings.Join(paths[:maxListed], ", "), len(paths)-maxListed)
	}
	return strings.Join(paths, ", ")
}

func listPathsVerb(paths []string) string {
	if len(paths) == 1 {
		return listPaths(paths) + " is"
	}
	return listPaths(paths) + " are"
}

func listRaw(items []string) string {
	if len(items) > maxListed {
		return strings.Join(items[:maxListed], "; ") + fmt.Sprintf("; and %d more", len(items)-maxListed)
	}
	return strings.Join(items, "; ")
}

func pathsOnly(items []string) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i], _, _ = strings.Cut(it, " (")
	}
	return out
}
