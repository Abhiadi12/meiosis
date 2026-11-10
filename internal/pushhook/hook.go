// Package pushhook is the policy meiosis applies to Git pushes. Git runs it
// through the pre-receive and post-receive hooks the server installs in each
// repository it serves.
//
// pre-receive decides: who is pushing (a verified capability token, or nobody if
// the server allows that), which intent the push is under, and whether every
// path it changes is in scope (FR-3.4), refusing the push with a message Git
// shows the pusher. It writes nothing but a small plan file. post-receive
// records: for each ref that actually moved it appends a signed RefUpdate with
// the world hash of the new tree (FR-2.2), creating an implicit "warn"-mode
// intent when the push named none (IF-1).
package pushhook

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/scope"
	"github.com/mindfire-test/meiosis/internal/secrets"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
	"github.com/mindfire-test/meiosis/pkg/worlds"
)

// Environment variables the server sets for the hooks.
const (
	EnvDB        = "MEIOSIS_DB"
	EnvSignerKey = "MEIOSIS_SIGNER_KEY"
	EnvSigner    = "MEIOSIS_SIGNER"
	EnvIssuerKey = "MEIOSIS_ISSUER_KEY"
	EnvRepo      = "MEIOSIS_REPO"
	EnvStrict    = "MEIOSIS_STRICT"
	EnvToken     = "MEIOSIS_PUSH_TOKEN"
	EnvSecrets   = "MEIOSIS_SECRETS"
)

// AnonymousPrincipal is who a push is attributed to when the server runs
// without capability enforcement.
const AnonymousPrincipal = "human:anonymous"

// Env is everything the hooks need to know about the server that ran them.
type Env struct {
	DB            string
	SignerKeyPath string
	Signer        string // principal that signs ref update records
	IssuerKeyPath string // empty: the server does not enforce tokens
	Repo          string
	Strict        bool
	Token         string // the pusher's bearer token
	Secrets       secrets.Mode
	PushOptions   []string
	GitDir        string
}

// EnvFromProcess reads the hook environment git and the server set.
func EnvFromProcess() (Env, error) {
	e := Env{
		DB: os.Getenv(EnvDB), SignerKeyPath: os.Getenv(EnvSignerKey), Signer: os.Getenv(EnvSigner),
		IssuerKeyPath: os.Getenv(EnvIssuerKey), Repo: os.Getenv(EnvRepo), Strict: os.Getenv(EnvStrict) == "1",
		Token: os.Getenv(EnvToken), GitDir: os.Getenv("GIT_DIR"),
	}
	if e.DB == "" || e.SignerKeyPath == "" || e.Signer == "" || e.Repo == "" {
		return Env{}, fmt.Errorf("the hook was not started by `mei serve`: %s, %s, %s and %s must be set", EnvDB, EnvSignerKey, EnvSigner, EnvRepo)
	}
	mode, ok := secrets.ParseMode(os.Getenv(EnvSecrets))
	if !ok {
		return Env{}, fmt.Errorf("%s=%q is not off, warn or block", EnvSecrets, os.Getenv(EnvSecrets))
	}
	e.Secrets = mode
	if n, err := strconv.Atoi(os.Getenv("GIT_PUSH_OPTION_COUNT")); err == nil {
		for i := 0; i < n; i++ {
			e.PushOptions = append(e.PushOptions, os.Getenv("GIT_PUSH_OPTION_"+strconv.Itoa(i)))
		}
	}
	return e, nil
}

// Update is one line of a hook's input: a ref moving from Old to New.
type Update struct {
	Old, New, Ref string
}

// ReadUpdates parses the "<old> <new> <ref>" lines git feeds a receive hook.
func ReadUpdates(r io.Reader) ([]Update, error) {
	var updates []Update
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("unexpected hook input %q", line)
		}
		updates = append(updates, Update{Old: f[0], New: f[1], Ref: f[2]})
	}
	return updates, scanner.Err()
}

// Rejection is returned by PreReceive when the push must be refused. Its
// reasons are shown to the pusher.
type Rejection struct{ Reasons []string }

func (r *Rejection) Error() string { return strings.Join(r.Reasons, "; ") }

// maxListed bounds how many offending paths a rejection spells out.
const maxListed = 15

type session struct {
	env     Env
	repo    gitops.Repo
	backend *sqlite.Store
	store   *graph.Store
	token   *specv1.CapabilityToken
	issuer  ed25519.PublicKey
	pusher  string
	intent  *graph.IntentView // the intent the push names or its token binds; nil if neither
}

func open(env Env) (*session, error) {
	backend, err := sqlite.Open(env.DB)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return &session{env: env, repo: gitops.Repo{}, backend: backend, store: graph.NewStore(backend)}, nil
}

func (s *session) close() { _ = s.backend.Close() }

// authenticate establishes who is pushing. With an issuer key configured a
// valid capability token that permits git_push is required; without one the
// push is anonymous, unless the repository is strict, which forbids that.
func (s *session) authenticate(now time.Time) error {
	if s.env.IssuerKeyPath == "" {
		if s.env.Strict {
			return &Rejection{Reasons: []string{"this repository is strict: a push needs a capability token, and the server has no issuer key to check one against"}}
		}
		s.pusher = AnonymousPrincipal
		return nil
	}
	data, err := os.ReadFile(s.env.IssuerKeyPath)
	if err != nil {
		return fmt.Errorf("read issuer key: %w", err)
	}
	if s.issuer, err = crypto.LoadEncodedPublicKey(string(data)); err != nil {
		return fmt.Errorf("load issuer key: %w", err)
	}
	if s.env.Token == "" {
		return &Rejection{Reasons: []string{"a capability token is required to push; none was presented"}}
	}
	token, err := identity.ParseBearer(s.env.Token)
	if err != nil {
		return &Rejection{Reasons: []string{"the capability token could not be read: " + err.Error()}}
	}
	if err = identity.Verify(token, s.issuer, identity.NewStoreRevocationList(s.backend), now); err != nil {
		return &Rejection{Reasons: []string{"the capability token was refused: " + err.Error()}}
	}
	if err = identity.CheckOperation(token, "git_push"); err != nil {
		return &Rejection{Reasons: []string{err.Error()}}
	}
	s.token, s.pusher = &token, token.Principal
	return nil
}

// optionValue returns the value of a "key=value" push option.
func (e Env) optionValue(key string) string {
	for _, o := range e.PushOptions {
		if v, ok := strings.CutPrefix(o, key+"="); ok {
			return v
		}
	}
	return ""
}

// resolveIntent works out which intent the push is under: the one its token is
// bound to, or the one named with `git push -o intent=<id>`. A push that names
// none is implicit and is handled after it succeeds.
func (s *session) resolveIntent(ctx context.Context) error {
	named := s.env.optionValue("intent")
	var want string
	switch {
	case s.token != nil && s.token.Intent != specv1.CapabilityTokenAnyIntent:
		want = s.token.Intent
		if named != "" && !strings.HasPrefix(want, named) {
			return &Rejection{Reasons: []string{fmt.Sprintf("the push names intent %s but its capability token is bound to %s", named, want)}}
		}
	case named != "":
		want = named
	default:
		return nil
	}
	views, err := s.store.ListIntentViews(ctx, true)
	if err != nil {
		return err
	}
	var matches []graph.IntentView
	for _, v := range views {
		if v.ID == want || strings.HasPrefix(v.ID, want) {
			matches = append(matches, v)
		}
	}
	switch len(matches) {
	case 0:
		return &Rejection{Reasons: []string{fmt.Sprintf("no intent matches %q", want)}}
	case 1:
	default:
		return &Rejection{Reasons: []string{fmt.Sprintf("intent %q is ambiguous: it matches %d intents", want, len(matches))}}
	}
	if !matches[0].Open() {
		return &Rejection{Reasons: []string{fmt.Sprintf("intent %s is not open for new work (status %s, superseded by %q)", matches[0].ID, matches[0].CurrentStatus, matches[0].SupersededBy)}}
	}
	s.intent = &matches[0]
	return nil
}

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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
// *Rejection refuses it, and the reasons are also written to out (git shows
// them to the pusher as "remote: ..." lines).
func PreReceive(ctx context.Context, env Env, updates []Update, out io.Writer) error {
	s, err := open(env)
	if err != nil {
		return err
	}
	defer s.close()
	err = s.preReceive(ctx, updates, out)
	var rej *Rejection
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
			reasons = append(reasons, fmt.Sprintf("%s: deleting a ref is not allowed", u.Ref))
			continue
		}
		p, hard, err := s.examine(ctx, u, now)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", u.Ref, err))
			continue
		}
		reasons = append(reasons, hard...)
		plans = append(plans, p)
	}
	if len(reasons) > 0 {
		return &Rejection{Reasons: reasons}
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
func (s *session) examine(ctx context.Context, u Update, now time.Time) (plan, []string, error) {
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

// PostReceive records every ref that moved: a signed RefUpdate with the new
// tree's world hash, under the push's intent or an implicit one.
func PostReceive(ctx context.Context, env Env, updates []Update, out io.Writer) error {
	s, err := open(env)
	if err != nil {
		return err
	}
	defer s.close()
	keyData, err := os.ReadFile(env.SignerKeyPath)
	if err != nil {
		return fmt.Errorf("read signer key: %w", err)
	}
	keys, err := crypto.LoadEncodedKeyPair(string(keyData), "")
	if err != nil {
		return fmt.Errorf("load signer key: %w", err)
	}

	var failures []string
	for _, u := range updates {
		if gitops.IsZero(u.New) {
			continue
		}
		if err := s.record(ctx, u, keys, out); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", u.Ref, err))
			_, _ = fmt.Fprintf(out, "meiosis: WARNING: %s was updated but recording it failed: %v\n", u.Ref, err)
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (s *session) record(ctx context.Context, u Update, keys crypto.KeyPair, out io.Writer) error {
	path := s.env.planPath(u.Ref, u.New)
	p, err := readPlan(path)
	if err != nil {
		return fmt.Errorf("no plan from pre-receive (%w)", err)
	}
	defer func() { _ = os.Remove(path) }()

	var token *specv1.CapabilityToken
	if s.env.Token != "" {
		// pre-receive verified it; here it is only embedded so the record carries
		// the chain the push was made under.
		if t, tErr := identity.ParseBearer(s.env.Token); tErr == nil {
			token = &t
		}
	}

	implicit := p.Intent == ""
	intentID := p.Intent
	if implicit {
		subject, _ := s.repo.Subject(ctx, u.New)
		if subject == "" {
			subject = u.New[:12]
		}
		intent, _, derr := s.store.DeriveIntent(ctx, graph.DeriveIntentParams{
			Repo:      s.env.Repo,
			Task:      fmt.Sprintf("Push to %s: %s", shortRef(u.Ref), subject),
			Scope:     specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeWarn},
			CreatedBy: s.env.Signer,
		}, keys.PrivateKey)
		if derr != nil {
			return fmt.Errorf("derive an implicit intent: %w", derr)
		}
		intentID = intent.ID
	}

	old := u.Old
	if gitops.IsZero(old) {
		old = ""
	}
	rec, err := s.store.RecordRefUpdate(ctx, graph.RefUpdateParams{
		Repo: s.env.Repo, Ref: u.Ref, OldCommit: old, NewCommit: u.New,
		World: p.World, BaseWorld: p.BaseWorld, PushedBy: p.Pusher, Token: token,
		Intent: intentID, ImplicitIntent: implicit, ChangedPaths: p.Changed, ScopeViolations: p.Violations,
		SecretScan: string(s.env.Secrets), SecretFindings: p.Findings, SecretScanTruncated: p.Truncated,
		SignedBy: s.env.Signer,
	}, keys.PrivateKey)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("%s -> world %s (record %s", u.Ref, rec.World.String()[:12], rec.ID)
	if rec.Attempt != "" {
		line += ", delivers attempt " + rec.Attempt
	}
	_, _ = fmt.Fprintf(out, "meiosis: %s)\n", line)
	return nil
}

func shortRef(ref string) string {
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		if s, ok := strings.CutPrefix(ref, prefix); ok {
			return s
		}
	}
	return ref
}

// maxScanBytes bounds how much diff a push is scanned over.
const maxScanBytes = 64 << 20

// scanSecrets looks for credentials in what a ref update adds: in the names of
// the paths it touches and in the lines it adds. With scanning off it does nothing.
// Findings name the place and the rule, never the secret.
func (s *session) scanSecrets(ctx context.Context, u Update, paths []string) (findings []specv1.SecretFinding, truncated bool, err error) {
	if s.env.Secrets == secrets.ModeOff {
		return nil, false, nil
	}
	seen := map[specv1.SecretFinding]bool{}
	add := func(f secrets.Finding) {
		sf := specv1.SecretFinding{Path: f.Path, Line: f.Line, Rule: f.Rule, Confidence: string(f.Confidence)}
		if !seen[sf] {
			seen[sf] = true
			findings = append(findings, sf)
		}
	}
	for _, p := range paths {
		for _, f := range secrets.ScanPath(p) {
			add(f)
		}
	}
	truncated, err = s.repo.EachAddedLine(ctx, u.Ref, u.Old, u.New, maxScanBytes, func(path string, line int, text string) {
		for _, f := range secrets.ScanLine(text) {
			f.Path, f.Line = path, line
			add(f)
		}
	})
	if err != nil {
		return nil, false, err
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings, truncated, nil
}

func describe(f specv1.SecretFinding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d (%s)", f.Path, f.Line, f.Rule)
	}
	return fmt.Sprintf("%s (%s)", f.Path, f.Rule)
}

func describeAll(fs []specv1.SecretFinding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = describe(f)
	}
	return out
}
