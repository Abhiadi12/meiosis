// Package gitserver exposes a Git smart HTTP server for repositories below a
// configured project root.
package gitserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Handler serves repositories from ProjectRoot through Git's smart HTTP
// backend. The backend supports both upload-pack and receive-pack operations.
//
// Responses are streamed: a clone's pack goes to the client as git produces it
// and is never held whole in memory.
type Handler struct {
	ProjectRoot string
	GitBinary   string
	// ExtraEnv, if set, returns extra environment variables ("KEY=value") for the
	// git process serving r. The server uses it to tell the receive hooks who is
	// pushing.
	ExtraEnv func(r *http.Request) []string
	// Logf, if set, receives diagnostics from the git process.
	Logf func(format string, args ...any)
}

// NewHandler creates a smart HTTP handler rooted at projectRoot. Repositories
// are addressed by their URL path, for example /repo.git.
func NewHandler(projectRoot string) (*Handler, error) {
	root, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}
	if projectRoot == "" {
		projectRoot = root
	} else if !filepath.IsAbs(projectRoot) {
		projectRoot = filepath.Join(root, projectRoot)
	}
	return &Handler{ProjectRoot: projectRoot, GitBinary: "git"}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := validatePath(r.URL.Path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.serve(w, r); err != nil {
		h.logf("git http-backend for %s %s: %v", r.Method, r.URL.Path, err)
	}
}

func (h *Handler) logf(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
	}
}

// serve runs git http-backend for r and relays its CGI response. An error
// before any output is sent becomes a 500; after that the status is already
// committed and the error is only returned for logging.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) error {
	gitBinary := h.GitBinary
	if gitBinary == "" {
		gitBinary = "git"
	}
	// The server explicitly exposes receive-pack because push is part of the
	// smart HTTP contract. Authentication and authorization belong at the HTTP
	// boundary in front of this handler.
	cmd := exec.CommandContext(r.Context(), gitBinary, "-c", "http.receivepack=true", "http-backend")
	cmd.Stdin = r.Body
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return err
	}
	cmd.Env = h.environment(r)
	if err = cmd.Start(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return fmt.Errorf("start git http-backend: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 1<<16)
	copyErr := relayCGI(w, reader)
	if copyErr != nil {
		// The client went away or the response was malformed: stop git.
		_ = stdout.Close()
	}
	waitErr := cmd.Wait()
	if copyErr != nil {
		return copyErr
	}
	if waitErr != nil {
		return fmt.Errorf("%w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (h *Handler) environment(r *http.Request) []string {
	env := append([]string{}, os.Environ()...)
	setEnv := func(key, value string) {
		prefix := key + "="
		for index, item := range env {
			if strings.HasPrefix(item, prefix) {
				env[index] = prefix + value
				return
			}
		}
		env = append(env, prefix+value)
	}
	setEnv("GIT_PROJECT_ROOT", h.ProjectRoot)
	setEnv("GIT_HTTP_EXPORT_ALL", "1")
	setEnv("PATH_INFO", r.URL.Path)
	setEnv("REQUEST_METHOD", r.Method)
	setEnv("QUERY_STRING", r.URL.RawQuery)
	setEnv("CONTENT_TYPE", r.Header.Get("Content-Type"))
	// A request body of unknown length (chunked) has no CONTENT_LENGTH; git then
	// reads it to the end.
	if r.ContentLength >= 0 {
		setEnv("CONTENT_LENGTH", strconv.FormatInt(r.ContentLength, 10))
	}
	setEnv("REMOTE_ADDR", r.RemoteAddr)
	setEnv("SERVER_PROTOCOL", r.Proto)
	setEnv("HTTP_HOST", r.Host)
	for key, values := range r.Header {
		if len(values) == 0 || strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie") {
			continue // credentials are the server's business, not git's
		}
		setEnv("HTTP_"+strings.ReplaceAll(strings.ToUpper(key), "-", "_"), strings.Join(values, ","))
	}
	if h.ExtraEnv != nil {
		for _, kv := range h.ExtraEnv(r) {
			if key, value, ok := strings.Cut(kv, "="); ok {
				setEnv(key, value)
			}
		}
	}
	return env
}

// limitedBuffer keeps the first few KiB of what is written to it.
type limitedBuffer struct{ buf []byte }

const limitedBufferMax = 8 << 10

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := limitedBufferMax - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return string(b.buf) }

// relayCGI reads a CGI response (headers, blank line, body) and writes it to w,
// flushing as the body arrives.
func relayCGI(w http.ResponseWriter, reader *bufio.Reader) error {
	header, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return fmt.Errorf("parse git http-backend headers: %w", err)
	}
	status := http.StatusOK
	if value := header.Get("Status"); value != "" {
		fields := strings.Fields(value)
		if len(fields) == 0 {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return errors.New("empty git http-backend status")
		}
		code, parseErr := strconv.Atoi(fields[0])
		if parseErr != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return fmt.Errorf("parse git http-backend status: %w", parseErr)
		}
		status = code
	}
	for key, values := range header {
		if strings.EqualFold(key, "Status") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(status)

	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func validatePath(requestPath string) error {
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") {
		return errors.New("invalid repository path")
	}
	clean := path.Clean(requestPath)
	if clean != requestPath || strings.Contains(requestPath, "..") {
		return errors.New("invalid repository path")
	}
	return nil
}

var _ http.Handler = (*Handler)(nil)
