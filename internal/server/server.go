// Package server assembles `mei serve`: Git smart HTTP for the repositories it
// owns, with capability-token authentication in front and meiosis's push policy
// behind (via git's receive hooks), plus the MCP endpoint, from one process.
package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/mindfire-test/meiosis/internal/gitops"
	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/mcp"
	"github.com/mindfire-test/meiosis/internal/metrics"
	"github.com/mindfire-test/meiosis/internal/pushhook"
	"github.com/mindfire-test/meiosis/internal/secrets"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	"github.com/mindfire-test/meiosis/pkg/gitserver"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// Config is what the server needs.
type Config struct {
	// Addr to listen on, e.g. 127.0.0.1:8484.
	Addr string
	// ReposDir holds the bare repositories, one directory NAME.git each.
	ReposDir string
	// Repos names the repositories to create if absent. Existing repositories in
	// ReposDir are served too.
	Repos []string
	// DB is the SQLite database shared with the CLI and the MCP daemon.
	DB string
	// Mei is the path of the mei binary the receive hooks run.
	Mei string
	// Git is the git binary; empty means "git" on PATH.
	Git string

	// SignerKeyPath and Signer identify the server: it signs the record of each
	// ref update as Signer.
	SignerKeyPath string
	Signer        string
	// IssuerKeyPath is the trusted issuer's public key. Empty means the server
	// does not require capability tokens.
	IssuerKeyPath string
	// Strict records that the repository forbids running without tokens.
	Strict bool
	// Secrets is the credential-scanning mode for pushes: "off", "warn" (the
	// default) or "block".
	Secrets string

	// Agent and AgentKeyPath are the principal and key the /mcp endpoint acts as.
	Agent        string
	AgentKeyPath string

	// Version is reported by the metrics.
	Version string
	// MetricsRemote allows /metrics to be read from non-loopback addresses.
	MetricsRemote bool

	Logger *slog.Logger
}

// Server is a running (or runnable) meiosis server.
type Server struct {
	cfg     Config
	store   *graph.Store
	backend *sqlite.Store
	issuer  ed25519.PublicKey
	revoked identity.RevocationChecker
	mcp     *mcp.Server
	git     *gitserver.Handler
	log     *slog.Logger

	metrics  *metrics.Registry
	requests *metrics.Counter
	latency  *metrics.Histogram
	tools    *metrics.Counter
	toolTime *metrics.Histogram
}

var repoNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// SanitizeRepoName turns an arbitrary directory name into a repository name.
func SanitizeRepoName(name string) string {
	name = strings.Trim(regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(name, "-"), "-.")
	if name == "" {
		return "repo"
	}
	return name
}

// New prepares a server: opens the store, creates the repositories, installs the
// hooks and builds the handlers. It does not listen.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.ReposDir == "" || cfg.DB == "" || cfg.Mei == "" || cfg.SignerKeyPath == "" || cfg.Signer == "" {
		return nil, errors.New("server: ReposDir, DB, Mei, SignerKeyPath and Signer are required")
	}
	if _, ok := secrets.ParseMode(cfg.Secrets); !ok {
		return nil, fmt.Errorf("server: secrets mode %q is not off, warn or block", cfg.Secrets)
	}
	if cfg.Strict && cfg.IssuerKeyPath == "" {
		return nil, errors.New("server: strict mode requires an issuer key: every push and fetch must carry a capability token")
	}
	s := &Server{cfg: cfg, log: cfg.Logger, metrics: metrics.NewRegistry()}
	s.requests = s.metrics.Counter("meiosis_http_requests_total", "HTTP requests served, by route and status code.", "route", "code")
	s.latency = s.metrics.Histogram("meiosis_http_request_duration_seconds", "HTTP request duration in seconds, by route.", nil, "route")
	s.tools = s.metrics.Counter("meiosis_tool_calls_total", "Tool calls, by tool and outcome (ok or the error class).", "tool", "outcome")
	s.toolTime = s.metrics.Histogram("meiosis_tool_call_duration_seconds", "Tool call duration in seconds, by tool.", nil, "tool")
	s.metrics.SetGauge("meiosis_up", "Whether the server is running.", 1, nil)
	version := cfg.Version
	if version == "" {
		version = "dev"
	}
	s.metrics.SetGauge("meiosis_build_info", "The server's version.", 1, []string{"version"}, version)

	backend, err := sqlite.Open(cfg.DB)
	if err != nil {
		return nil, fmt.Errorf("server: open store: %w", err)
	}
	s.backend, s.store = backend, graph.NewStore(backend)
	s.revoked = identity.NewStoreRevocationList(backend)

	if cfg.IssuerKeyPath != "" {
		data, readErr := os.ReadFile(cfg.IssuerKeyPath)
		if readErr != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("server: read issuer key: %w", readErr)
		}
		if s.issuer, err = crypto.LoadEncodedPublicKey(string(data)); err != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("server: load issuer key: %w", err)
		}
	}

	for _, name := range cfg.Repos {
		if !repoNamePattern.MatchString(name) {
			_ = backend.Close()
			return nil, fmt.Errorf("server: %q is not a usable repository name", name)
		}
		if err = gitops.InitBare(context.Background(), cfg.Git, filepath.Join(cfg.ReposDir, name+".git")); err != nil {
			_ = backend.Close()
			return nil, err
		}
	}
	if err = s.installHooks(); err != nil {
		_ = backend.Close()
		return nil, err
	}

	if cfg.AgentKeyPath != "" && cfg.Agent != "" {
		data, readErr := os.ReadFile(cfg.AgentKeyPath)
		if readErr != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("server: read agent key: %w", readErr)
		}
		keys, loadErr := crypto.LoadEncodedKeyPair(string(data), "")
		if loadErr != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("server: load agent key: %w", loadErr)
		}
		s.mcp = mcp.NewServer(s.store, cfg.Agent, keys.PrivateKey)
		s.mcp.Observer = s.observeTool
		s.mcp.IssuerKey = s.issuer
		if s.issuer != nil {
			s.mcp.Revocation = s.revoked
		}
	}

	s.git = &gitserver.Handler{ProjectRoot: cfg.ReposDir, GitBinary: cfg.Git, ExtraEnv: s.hookEnv, Logf: func(format string, args ...any) {
		s.log.Warn(fmt.Sprintf(format, args...))
	}}
	return s, nil
}

// Close releases the store.
func (s *Server) Close() error { return s.backend.Close() }

// installHooks (re)writes the receive hooks in every repository served, so a
// moved mei binary is picked up on the next start.
func (s *Server) installHooks() error {
	entries, err := os.ReadDir(s.cfg.ReposDir)
	if err != nil {
		return fmt.Errorf("server: read %s: %w", s.cfg.ReposDir, err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".git") {
			if err := gitops.InstallHooks(filepath.Join(s.cfg.ReposDir, e.Name()), s.cfg.Mei); err != nil {
				return err
			}
		}
	}
	return nil
}

// Handler returns the HTTP handler: /healthz, /mcp, and the repositories.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	if s.mcp != nil {
		mux.Handle("/mcp", s.mcp)
		mux.HandleFunc("/api/v1/", s.mcp.ServeAPI)
	}
	mux.Handle("/metrics", s.metrics.Handler(s.cfg.MetricsRemote))
	mux.HandleFunc("/", s.serveGit)
	return s.instrument(mux)
}

// observeTool records one tool call.
func (s *Server) observeTool(tool string, took time.Duration, err error) {
	outcome := "ok"
	if err != nil {
		_, outcome = mcp.Classify(err)
	}
	s.tools.Inc(tool, outcome)
	s.toolTime.Observe(took.Seconds(), tool)
}

// instrument counts and times every request, by a small fixed set of routes so
// the number of series cannot be inflated by a client.
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		s.serveRecovering(rec, r, next)
		route := routeOf(r.URL.Path)
		s.requests.Inc(route, strconv.Itoa(rec.status))
		s.latency.Observe(time.Since(started).Seconds(), route)
	})
}

// serveRecovering runs next and turns a panic in a handler into a logged 500,
// so one bad request cannot take the server down or leave the client hanging.
// http.ErrAbortHandler is passed through: it is how a handler aborts on purpose.
func (s *Server) serveRecovering(rec *statusRecorder, r *http.Request, next http.Handler) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		if v == http.ErrAbortHandler { //nolint:errorlint // net/http documents comparing the recovered value directly
			panic(v)
		}
		s.log.Error("handler panic", "method", r.Method, "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
		if !rec.wrote {
			http.Error(rec, "internal server error", http.StatusInternalServerError)
		}
	}()
	next.ServeHTTP(rec, r)
}

func routeOf(p string) string {
	switch {
	case p == "/healthz":
		return "healthz"
	case p == "/metrics":
		return "metrics"
	case p == "/mcp":
		return "mcp"
	case strings.HasPrefix(p, "/api/v1/"):
		return "api"
	}
	if _, ok := repoOf(p); ok {
		return "git"
	}
	return "other"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

// Flush keeps streaming responses (a clone's pack) streaming.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Serve listens on cfg.Addr until ctx is done, then shuts down cleanly.
func (s *Server) Serve(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Addr, err)
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener is Serve on an existing listener.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	// No read or write timeout: a git push or clone legitimately streams for a
	// long time. Slow clients are bounded by the header and idle timeouts.
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
		}
		if serveErr := <-errc; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
}

type gitOp string

const (
	opFetch gitOp = "git_fetch"
	opPush  gitOp = "git_push"
)

// classify says whether a smart-HTTP request reads or writes the repository.
func classify(r *http.Request) gitOp {
	if r.URL.Query().Get("service") == "git-receive-pack" || strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
		return opPush
	}
	return opFetch
}

// repoOf extracts the repository name from a smart-HTTP path: /NAME.git/...
func repoOf(urlPath string) (string, bool) {
	first, _, _ := strings.Cut(strings.TrimPrefix(urlPath, "/"), "/")
	name, ok := strings.CutSuffix(first, ".git")
	return name, ok && repoNamePattern.MatchString(name)
}

// credentials extracts the bearer token from an Authorization header: either
// "Bearer <token>" or HTTP Basic with the token as the password (what git sends
// when a credential helper supplies one).
func credentials(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if token, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(token)
	}
	if _, password, ok := r.BasicAuth(); ok {
		return password
	}
	return ""
}

type authedKey struct{}

// authenticate verifies the request's token for op. It returns the token string
// to hand to the hooks, or writes an error response and returns false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, op gitOp) (string, bool) {
	if s.issuer == nil {
		return "", true
	}
	raw := credentials(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="meiosis"`)
		http.Error(w, "a capability token is required (send it as a bearer token, or as the password of HTTP Basic)", http.StatusUnauthorized)
		return "", false
	}
	token, err := identity.ParseBearer(raw)
	if err == nil {
		err = identity.Verify(token, s.issuer, s.revoked, time.Now())
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="meiosis"`)
		http.Error(w, "capability token refused: "+err.Error(), http.StatusUnauthorized)
		return "", false
	}
	if err = identity.CheckOperation(token, string(op)); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return "", false
	}
	return raw, true
}

func (s *Server) serveGit(w http.ResponseWriter, r *http.Request) {
	name, ok := repoOf(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(filepath.Join(s.cfg.ReposDir, name+".git")); err != nil { //nolint:gosec // name was validated by repoOf against repoNamePattern
		http.NotFound(w, r)
		return
	}
	token, ok := s.authenticate(w, r, classify(r))
	if !ok {
		return
	}
	s.log.Info("git", "method", r.Method, "path", r.URL.Path, "op", string(classify(r)), "remote", r.RemoteAddr)
	ctx := context.WithValue(r.Context(), authedKey{}, token)
	s.git.ServeHTTP(w, r.WithContext(ctx))
}

// hookEnv tells the receive hooks what the server knows: where the store and
// keys are, which repository this is and, for a push, who sent it.
func (s *Server) hookEnv(r *http.Request) []string {
	name, _ := repoOf(r.URL.Path)
	token, _ := r.Context().Value(authedKey{}).(string)
	strict := "0"
	if s.cfg.Strict {
		strict = "1"
	}
	env := []string{
		pushhook.EnvDB + "=" + s.cfg.DB,
		pushhook.EnvSignerKey + "=" + s.cfg.SignerKeyPath,
		pushhook.EnvSigner + "=" + s.cfg.Signer,
		pushhook.EnvRepo + "=" + name,
		pushhook.EnvStrict + "=" + strict,
		pushhook.EnvIssuerKey + "=" + s.cfg.IssuerKeyPath,
		pushhook.EnvToken + "=" + token,
		pushhook.EnvSecrets + "=" + s.cfg.Secrets,
	}
	return env
}

// Store exposes the graph store the server writes to.
func (s *Server) Store() *graph.Store { return s.store }
