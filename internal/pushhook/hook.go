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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/secrets"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
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
		for i := range n {
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

// RejectionError is returned by PreReceive when the push must be refused. Its
// reasons are shown to the pusher.
type RejectionError struct{ Reasons []string }

func (r *RejectionError) Error() string { return strings.Join(r.Reasons, "; ") }

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
			return &RejectionError{Reasons: []string{"this repository is strict: a push needs a capability token, and the server has no issuer key to check one against"}}
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
		return &RejectionError{Reasons: []string{"a capability token is required to push; none was presented"}}
	}
	token, err := identity.ParseBearer(s.env.Token)
	if err != nil {
		return &RejectionError{Reasons: []string{"the capability token could not be read: " + err.Error()}}
	}
	if err = identity.Verify(token, s.issuer, identity.NewStoreRevocationList(s.backend), now); err != nil {
		return &RejectionError{Reasons: []string{"the capability token was refused: " + err.Error()}}
	}
	if err = identity.CheckOperation(token, "git_push"); err != nil {
		return &RejectionError{Reasons: []string{err.Error()}}
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
			return &RejectionError{Reasons: []string{fmt.Sprintf("the push names intent %s but its capability token is bound to %s", named, want)}}
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
		return &RejectionError{Reasons: []string{fmt.Sprintf("no intent matches %q", want)}}
	case 1:
	default:
		return &RejectionError{Reasons: []string{fmt.Sprintf("intent %q is ambiguous: it matches %d intents", want, len(matches))}}
	}
	if !matches[0].Open() {
		return &RejectionError{Reasons: []string{fmt.Sprintf("intent %s is not open for new work (status %s, superseded by %q)", matches[0].ID, matches[0].CurrentStatus, matches[0].SupersededBy)}}
	}
	s.intent = &matches[0]
	return nil
}
