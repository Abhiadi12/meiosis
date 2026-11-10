package identity

import (
	"crypto/ed25519"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type actors struct {
	human, agentA, agentB crypto.KeyPair
}

func newActors(t testing.TB) actors {
	t.Helper()
	gen := func() crypto.KeyPair {
		k, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	return actors{gen(), gen(), gen()}
}

func i64(v int64) *int64 { return &v }

// rootFor issues a root token from the human to agent A, who holds agentA's key.
func (a actors) rootFor(t testing.TB, mutate func(*IssueParams)) specv1.CapabilityToken {
	t.Helper()
	p := IssueParams{
		Principal: "agent:a", IssuedBy: "human:lakin", Intent: specv1.CapabilityTokenAnyIntent,
		Scope:     specv1.Scope{Allow: []string{"src/**", "docs/**"}, Deny: []string{"src/secret/**"}, Mode: specv1.ScopeModeEnforce},
		HolderKey: a.agentA.PublicKey, TTL: time.Hour,
	}
	if mutate != nil {
		mutate(&p)
	}
	token, err := Issue(p, a.human.PrivateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	return token
}

func (a actors) delegateToB(t testing.TB, parent specv1.CapabilityToken, p DelegateParams) (specv1.CapabilityToken, error) {
	t.Helper()
	p.Principal, p.HolderKey = "agent:b", a.agentB.PublicKey
	return Delegate(parent, p, a.agentA.PrivateKey)
}

func narrowScope(allow ...string) *specv1.Scope {
	return &specv1.Scope{Allow: allow, Deny: []string{"src/secret/**"}, Mode: specv1.ScopeModeEnforce}
}

func TestDelegateIssuesAVerifiableNarrowerToken(t *testing.T) {
	a := newActors(t)
	root := a.rootFor(t, func(p *IssueParams) {
		p.Operations = []string{"attempt_open", "attempt_write", "capability_delegate"}
		p.SpendCeilingMicros = i64(1000)
	})
	child, err := a.delegateToB(t, root, DelegateParams{
		Scope: narrowScope("src/auth/**"), Operations: []string{"attempt_write"}, SpendCeilingMicros: i64(400), TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Delegate() error = %v", err)
	}
	if child.Principal != "agent:b" || child.IssuedBy != "agent:a" || child.Parent == nil || child.Parent.ID != root.ID {
		t.Fatalf("child = %+v", child)
	}
	if err := Verify(child, a.human.PublicKey, nil, time.Now()); err != nil {
		t.Fatalf("Verify(child) error = %v", err)
	}
	if err := Authorize(child, a.human.PublicKey, nil, "src/auth/login.go", time.Now()); err != nil {
		t.Fatalf("Authorize(in scope) error = %v", err)
	}
	if err := Authorize(child, a.human.PublicKey, nil, "docs/readme.md", time.Now()); !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("Authorize(outside the narrowed scope) = %v, want ErrScopeDenied", err)
	}
	if got := Origin(child); got != "human:lakin" {
		t.Fatalf("Origin() = %q, want the originating human", got)
	}
	links := Links(child)
	if len(links) != 2 || links[0].Principal != "agent:b" || links[1].Principal != "agent:a" || links[1].IssuedBy != "human:lakin" {
		t.Fatalf("Links() = %+v", links)
	}
	limits := SpendLimits(child)
	if len(limits) != 2 || limits[0].CeilingMicros != 400 || limits[1].CeilingMicros != 1000 {
		t.Fatalf("SpendLimits() = %+v, want the child's and its parent's ceilings", limits)
	}
}

func TestDelegateInheritsWhatIsNotOverridden(t *testing.T) {
	a := newActors(t)
	root := a.rootFor(t, func(p *IssueParams) {
		p.Operations = []string{"attempt_write", "capability_delegate"}
		p.SpendCeilingMicros = i64(50)
	})
	child, err := a.delegateToB(t, root, DelegateParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Scope.Allow) != 2 || len(child.Scope.Deny) != 1 || len(child.Operations) != 2 || *child.SpendCeilingMicros != 50 || child.Intent != root.Intent {
		t.Fatalf("an unspecified delegation should inherit everything: %+v", child)
	}
	if !child.ExpiresAt.Before(root.ExpiresAt.Add(time.Second)) {
		t.Fatalf("child expires %v, after its parent %v", child.ExpiresAt, root.ExpiresAt)
	}
	// Mutating the child must not reach back into the parent.
	child.Scope.Allow[0] = "tampered"
	if root.Scope.Allow[0] == "tampered" {
		t.Fatal("the child shares its scope slices with the parent")
	}
}

func TestDelegateRefusesToWiden(t *testing.T) {
	a := newActors(t)
	bound := "int_" + strings.Repeat("c", 52)
	cases := map[string]struct {
		mutateRoot func(*IssueParams)
		p          DelegateParams
	}{
		"allow outside parent":        {nil, DelegateParams{Scope: narrowScope("lib/**")}},
		"allow everything":            {nil, DelegateParams{Scope: narrowScope("**")}},
		"sibling tree":                {nil, DelegateParams{Scope: narrowScope("srcs/**")}},
		"drops the parent's deny":     {nil, DelegateParams{Scope: &specv1.Scope{Allow: []string{"src/auth/**"}, Mode: specv1.ScopeModeEnforce}}},
		"narrower deny than parent":   {nil, DelegateParams{Scope: &specv1.Scope{Allow: []string{"src/auth/**"}, Deny: []string{"src/secret/keys/**"}, Mode: specv1.ScopeModeEnforce}}},
		"relaxes enforce to warn":     {nil, DelegateParams{Scope: &specv1.Scope{Allow: []string{"src/**"}, Deny: []string{"src/secret/**"}, Mode: specv1.ScopeModeWarn}}},
		"operation outside parent":    {func(p *IssueParams) { p.Operations = []string{"attempt_write", "capability_delegate"} }, DelegateParams{Operations: []string{"attempt_commit"}}},
		"all operations from limited": {func(p *IssueParams) { p.Operations = []string{"attempt_write", "capability_delegate"} }, DelegateParams{Operations: []string{"*"}}},
		"no ceiling under a ceiling":  {func(p *IssueParams) { p.SpendCeilingMicros = i64(10) }, DelegateParams{Operations: nil}},
		"ceiling above parent":        {func(p *IssueParams) { p.SpendCeilingMicros = i64(10) }, DelegateParams{SpendCeilingMicros: i64(11)}},
		"other intent from bound":     {func(p *IssueParams) { p.Intent = bound }, DelegateParams{Intent: "int_" + strings.Repeat("d", 52)}},
		"any intent from bound":       {func(p *IssueParams) { p.Intent = bound }, DelegateParams{Intent: specv1.CapabilityTokenAnyIntent}},
		"outlives the parent":         {func(p *IssueParams) { p.TTL = time.Hour }, DelegateParams{TTL: 2 * time.Hour}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := a.rootFor(t, c.mutateRoot)
			if name == "no ceiling under a ceiling" {
				// Inheriting would be fine; explicitly clearing the ceiling is not possible
				// through Delegate, so build the wider child by hand and check Verify refuses it.
				child := handSigned(t, root, a.agentA.PrivateKey, func(c *specv1.CapabilityToken) { c.SpendCeilingMicros = nil })
				if err := Verify(child, a.human.PublicKey, nil, time.Now()); !errors.Is(err, ErrWidening) {
					t.Fatalf("Verify(hand-signed child without a ceiling) = %v, want ErrWidening", err)
				}
				return
			}
			_, err := a.delegateToB(t, root, c.p)
			if !errors.Is(err, ErrWidening) {
				t.Fatalf("Delegate() error = %v, want ErrWidening", err)
			}
		})
	}
}

func TestDelegateRefusesWhatCannotBeDelegated(t *testing.T) {
	a := newActors(t)
	root := a.rootFor(t, nil)

	if _, err := Delegate(root, DelegateParams{Principal: "agent:b"}, a.agentB.PrivateKey); !errors.Is(err, ErrNotDelegable) {
		t.Fatalf("a non-holder delegating = %v, want ErrNotDelegable", err)
	}
	noKey := a.rootFor(t, func(p *IssueParams) { p.HolderKey = nil })
	if _, err := a.delegateToB(t, noKey, DelegateParams{}); !errors.Is(err, ErrNotDelegable) {
		t.Fatalf("a token without a holder key = %v, want ErrNotDelegable", err)
	}
	limited := a.rootFor(t, func(p *IssueParams) { p.Operations = []string{"attempt_write"} })
	if _, err := a.delegateToB(t, limited, DelegateParams{}); !errors.Is(err, ErrNotDelegable) {
		t.Fatalf("a token without capability_delegate = %v, want ErrNotDelegable", err)
	}
	if _, err := Delegate(root, DelegateParams{Principal: "agent:a", HolderKey: a.agentA.PublicKey}, a.agentA.PrivateKey); err == nil {
		t.Fatal("delegating to oneself was accepted")
	}
	expired := a.rootFor(t, func(p *IssueParams) { p.IssuedAt = time.Now().Add(-2 * time.Hour); p.TTL = time.Hour })
	if _, err := a.delegateToB(t, expired, DelegateParams{}); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("delegating from an expired token = %v, want ErrTokenExpired", err)
	}
}

func TestDelegationDepthIsBounded(t *testing.T) {
	a := newActors(t)
	token := a.rootFor(t, nil)
	holder := a.agentA
	for depth := 1; depth <= specv1.MaxDelegationDepth; depth++ {
		next, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		token, err = Delegate(token, DelegateParams{Principal: "agent:n" + string(rune('a'+depth)), HolderKey: next.PublicKey}, holder.PrivateKey)
		if err != nil {
			t.Fatalf("delegation %d: %v", depth, err)
		}
		holder = next
	}
	if err := Verify(token, a.human.PublicKey, nil, time.Now()); err != nil {
		t.Fatalf("a chain at the maximum depth should verify: %v", err)
	}
	if _, err := Delegate(token, DelegateParams{Principal: "agent:too-deep", HolderKey: a.agentB.PublicKey}, holder.PrivateKey); !errors.Is(err, ErrWidening) {
		t.Fatalf("one delegation past the limit = %v, want ErrWidening", err)
	}
}

// handSigned builds a child of root signed by key, applying mutate before
// signing, bypassing Delegate's checks the way a misbehaving delegator could.
func handSigned(t testing.TB, root specv1.CapabilityToken, key ed25519.PrivateKey, mutate func(*specv1.CapabilityToken)) specv1.CapabilityToken {
	t.Helper()
	parent := root
	child := specv1.CapabilityToken{
		ID: "cap_" + strings.Repeat("e", 52), Principal: "agent:b", IssuedBy: root.Principal, Intent: root.Intent,
		Scope: cloneScope(root.Scope), IssuedAt: root.IssuedAt, ExpiresAt: root.ExpiresAt,
		Operations: root.Operations, SpendCeilingMicros: root.SpendCeilingMicros, Parent: &parent,
	}
	mutate(&child)
	sig, err := crypto.Sign(child, key)
	if err != nil {
		t.Fatal(err)
	}
	child.Signature = sig
	return child
}

// The check at issuance is not the only line of defence: whoever verifies a
// token re-checks that every link narrows its parent.
func TestVerifyRejectsHandSignedWideningAndForgedChains(t *testing.T) {
	a := newActors(t)
	root := a.rootFor(t, func(p *IssueParams) { p.Operations = []string{"attempt_write", "capability_delegate"} })
	now := time.Now()

	wider := handSigned(t, root, a.agentA.PrivateKey, func(c *specv1.CapabilityToken) { c.Scope.Allow = []string{"**"} })
	if err := Verify(wider, a.human.PublicKey, nil, now); !errors.Is(err, ErrWidening) {
		t.Errorf("hand-signed wider scope = %v, want ErrWidening", err)
	}
	moreOps := handSigned(t, root, a.agentA.PrivateKey, func(c *specv1.CapabilityToken) { c.Operations = []string{"attempt_write", "attempt_commit"} })
	if err := Verify(moreOps, a.human.PublicKey, nil, now); !errors.Is(err, ErrWidening) {
		t.Errorf("hand-signed extra operation = %v, want ErrWidening", err)
	}
	longer := handSigned(t, root, a.agentA.PrivateKey, func(c *specv1.CapabilityToken) { c.ExpiresAt = root.ExpiresAt.Add(time.Hour) })
	if err := Verify(longer, a.human.PublicKey, nil, now); !errors.Is(err, ErrWidening) {
		t.Errorf("hand-signed longer lifetime = %v, want ErrWidening", err)
	}

	// Signed by someone who does not hold the parent.
	forged := handSigned(t, root, a.agentB.PrivateKey, func(*specv1.CapabilityToken) {})
	if err := Verify(forged, a.human.PublicKey, nil, now); !errors.Is(err, ErrTokenAltered) {
		t.Errorf("signed by a non-holder = %v, want ErrTokenAltered", err)
	}
	// Claims to be issued by someone other than the parent's holder.
	liar := handSigned(t, root, a.agentA.PrivateKey, func(c *specv1.CapabilityToken) { c.IssuedBy = "agent:zzz" })
	if err := Verify(liar, a.human.PublicKey, nil, now); !errors.Is(err, ErrTokenAltered) {
		t.Errorf("wrong issuer = %v, want ErrTokenAltered", err)
	}

	// Tampering with the embedded parent breaks the child's signature.
	good, err := a.delegateToB(t, root, DelegateParams{})
	if err != nil {
		t.Fatal(err)
	}
	tampered := good
	parent := *good.Parent
	parent.Scope.Allow = []string{"**"}
	tampered.Parent = &parent
	if err = Verify(tampered, a.human.PublicKey, nil, now); err == nil {
		t.Error("a token whose embedded parent was altered verified")
	}

	// A chain that does not start at a human is not a chain of authority.
	agentRoot, err := Issue(IssueParams{
		Principal: "agent:a", IssuedBy: "agent:rogue", Intent: specv1.CapabilityTokenAnyIntent,
		Scope: root.Scope, HolderKey: a.agentA.PublicKey,
	}, a.human.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(agentRoot, a.human.PublicKey, nil, now); !errors.Is(err, ErrRootNotHuman) {
		t.Errorf("root issued by an agent = %v, want ErrRootNotHuman", err)
	}

	// A chain whose root was not signed by the trusted issuer fails.
	other := newActors(t)
	if err := Verify(good, other.human.PublicKey, nil, now); !errors.Is(err, ErrTokenAltered) {
		t.Errorf("verifying under the wrong issuer key = %v, want ErrTokenAltered", err)
	}
}

func TestRevokingAnAncestorRevokesEveryDelegation(t *testing.T) {
	a := newActors(t)
	root := a.rootFor(t, nil)
	child, err := a.delegateToB(t, root, DelegateParams{})
	if err != nil {
		t.Fatal(err)
	}
	list := NewMemoryRevocationList()
	if err := Verify(child, a.human.PublicKey, list, time.Now()); err != nil {
		t.Fatal(err)
	}
	list.Revoke(child.ID)
	if err := Verify(root, a.human.PublicKey, list, time.Now()); err != nil {
		t.Fatalf("revoking the child must not revoke the parent: %v", err)
	}
	if err := Verify(child, a.human.PublicKey, list, time.Now()); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("revoked child = %v", err)
	}

	child2, _ := a.delegateToB(t, root, DelegateParams{})
	list.Revoke(root.ID)
	if err := Verify(child2, a.human.PublicKey, list, time.Now()); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("a child of a revoked parent = %v, want ErrTokenRevoked", err)
	}
}

func TestVerifyRejectsAnExpiredAncestor(t *testing.T) {
	a := newActors(t)
	root := a.rootFor(t, func(p *IssueParams) { p.TTL = time.Minute })
	child, err := a.delegateToB(t, root, DelegateParams{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(child, a.human.PublicKey, nil, time.Now().Add(2*time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("after the parent expired = %v, want ErrTokenExpired", err)
	}
}

func TestCheckOperation(t *testing.T) {
	open := specv1.CapabilityToken{}
	star := specv1.CapabilityToken{Operations: []string{"*"}}
	limited := specv1.CapabilityToken{Operations: []string{"attempt_write"}}
	for name, tok := range map[string]specv1.CapabilityToken{"empty": open, "star": star} {
		if err := CheckOperation(tok, "attempt_commit"); err != nil {
			t.Errorf("%s token refused an operation: %v", name, err)
		}
	}
	if err := CheckOperation(limited, "attempt_write"); err != nil {
		t.Errorf("listed operation refused: %v", err)
	}
	if err := CheckOperation(limited, "attempt_commit"); !errors.Is(err, ErrOperationDenied) {
		t.Errorf("unlisted operation = %v, want ErrOperationDenied", err)
	}
}

func TestGlobCovers(t *testing.T) {
	for _, c := range []struct {
		outer, inner string
		want         bool
	}{
		{"src/**", "src/**", true},
		{"src/**", "src/a/**", true},
		{"src/**", "src/a/b.go", true},
		{"src/**", "src", false},
		{"**", "anything/at/all", true},
		{"**", "**", true},
		{"*", "a", true},
		{"*", "a/b", false},
		{"src/**/*.go", "src/a/b.go", true},
		{"src/**/*.go", "src/**/*_test.go", false},
		{"src/**/*.go", "src/**", false},
		{"a/**/**", "a", false},
		{"a*/**", "a*", false},
		{"*/a*/**", "*b/a/**", false},
		{"*/?/**/**", "[ab]/?", false},
		{"a/**", "a/**", true},
		{"a/**", "a/b/**", true},
		{"a/**/**", "a/**/**", true},
		{"src/**", "src/**/*", true},
		{"src/a/**", "src/**", false},
		{"src/*", "src/a", true},
		{"src/*", "src/a/b", false},
		{"src/*", "src/**", false},
		{"docs/**", "src/**", false},
		{"a/b", "a/b", true},
		{"a/b", "a/**", false},
		{"a?", "ab", true},
		{"a?", "a*", false},
		{"{a,b}/x", "a/x", false},
		{"{a,b}/x", "{a,b}/x", true},
		{"", "a", false},
		{"/a", "/a", true},
		{"/a", "a", false},
	} {
		if got := globCovers(c.outer, c.inner); got != c.want {
			t.Errorf("globCovers(%q, %q) = %t, want %t", c.outer, c.inner, got, c.want)
		}
	}
}

var (
	patSegs  = []string{"a", "b", "ab", "*", "**", "a*", "*b", "?", "[ab]"}
	pathSegs = []string{"a", "b", "ab", "c", "aab"}
)

func randPattern(r *rand.Rand) string {
	n := 1 + r.Intn(4)
	segs := make([]string, n)
	for i := range segs {
		segs[i] = patSegs[r.Intn(len(patSegs))]
	}
	return strings.Join(segs, "/")
}

func randPath(r *rand.Rand) string {
	n := 1 + r.Intn(5)
	segs := make([]string, n)
	for i := range segs {
		segs[i] = pathSegs[r.Intn(len(pathSegs))]
	}
	return strings.Join(segs, "/")
}

func matches(pattern, path string) bool {
	ok, err := doublestar.Match(pattern, path)
	return err == nil && ok
}

// Property: if globCovers(outer, inner) then every path inner matches, outer
// matches too. A false positive here would let a delegation widen scope.
func TestPropertyGlobCoversIsSound(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	covered := 0
	for range 30000 {
		outer, inner := randPattern(r), randPattern(r)
		if !globCovers(outer, inner) {
			continue
		}
		covered++
		for range 60 {
			path := randPath(r)
			if matches(inner, path) && !matches(outer, path) {
				t.Fatalf("globCovers(%q, %q) is true but %q matches inner and not outer", outer, inner, path)
			}
		}
	}
	if covered < 500 {
		t.Fatalf("only %d covering pairs generated; the property was barely exercised", covered)
	}
}

func randScope(r *rand.Rand, mode specv1.ScopeMode) specv1.Scope {
	s := specv1.Scope{Mode: mode}
	for n := 1 + r.Intn(2); n > 0; n-- {
		s.Allow = append(s.Allow, randPattern(r))
	}
	for n := r.Intn(3); n > 0; n-- {
		s.Deny = append(s.Deny, randPattern(r))
	}
	return s
}

func allowed(s specv1.Scope, path string) bool {
	for _, d := range s.Deny {
		if matches(d, path) {
			return false
		}
	}
	for _, a := range s.Allow {
		if matches(a, path) {
			return true
		}
	}
	return false
}

// Property (SRS §11.1: delegation narrowing): whenever a scope is accepted as a
// narrowing of its parent, no path it allows is one the parent forbids.
func TestPropertyAcceptedDelegationNeverWidensScope(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	accepted := 0
	for range 40000 {
		parent := randScope(r, specv1.ScopeModeEnforce)
		child := randScope(r, specv1.ScopeModeEnforce)
		if r.Intn(3) == 0 {
			// Often derive the child from the parent so acceptances are common.
			child = specv1.Scope{Allow: []string{parent.Allow[0]}, Deny: append([]string(nil), parent.Deny...), Mode: specv1.ScopeModeEnforce}
			if r.Intn(2) == 0 {
				child.Allow = []string{child.Allow[0] + "/" + pathSegs[r.Intn(len(pathSegs))]}
			}
		}
		if scopeNarrower(parent, child) != nil {
			continue
		}
		accepted++
		for range 80 {
			path := randPath(r)
			if allowed(child, path) && !allowed(parent, path) {
				t.Fatalf("parent %+v / child %+v accepted, but %q is allowed by the child and not by the parent", parent, child, path)
			}
		}
	}
	if accepted < 500 {
		t.Fatalf("only %d acceptances generated; the property was barely exercised", accepted)
	}
}

// Property: operations and spend ceilings never widen through an accepted chain.
func TestPropertyOperationsAndSpendOnlyNarrow(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	pick := func() []string {
		var out []string
		for _, op := range specv1.CapabilityOperations {
			if r.Intn(3) == 0 {
				out = append(out, op)
			}
		}
		if r.Intn(8) == 0 {
			return []string{"*"}
		}
		return out
	}
	for range 20000 {
		parent, child := pick(), pick()
		if operationsNarrower(parent, child) != nil {
			continue
		}
		for _, op := range specv1.CapabilityOperations {
			childHas := unrestricted(child) || hasOperation(child, op)
			parentHas := unrestricted(parent) || hasOperation(parent, op)
			if childHas && !parentHas {
				t.Fatalf("parent ops %v / child ops %v accepted, but %s is only in the child", parent, child, op)
			}
		}
	}
}
