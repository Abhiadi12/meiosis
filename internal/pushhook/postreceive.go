package pushhook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/secrets"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

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
