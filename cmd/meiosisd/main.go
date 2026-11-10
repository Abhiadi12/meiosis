// Command meiosisd is the long-running meiosis daemon. It serves the agent tools
// over MCP (stdio, a Unix socket or HTTP) against one repository, with
// capability enforcement on by default. `mei serve` runs the same code together
// with the Git server for a single-command first run.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/internal/identity"
	"github.com/mindfire-test/meiosis/internal/mcp"
	"github.com/mindfire-test/meiosis/internal/server"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "meiosisd:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("meiosisd", flag.ContinueOnError)
	principal := fs.String("principal", "", "principal this daemon signs as, e.g. agent:impl-3")
	keyPath := fs.String("key", "", "path to this principal's Ed25519 private key (base64 or PEM)")
	dbPath := fs.String("db", "meiosisd.db", "path to the SQLite database")
	socketPath := fs.String("socket", "", "optional UNIX socket path to also listen on, in addition to stdio")
	issuerPubKeyPath := fs.String("issuer-pubkey", "", "path to a trusted issuer's Ed25519 public key (base64 or PEM); every tool call must carry a capability token signed by this issuer (FR-1.3). Default: human.public.key beside the database, as `mei init` leaves it")
	allowUnauth := fs.Bool("allow-unauthenticated", false, "serve tool calls without capability tokens. Refused in a repository whose config says strict: true")
	printVersion := fs.Bool("version", false, "print the meiosisd version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *printVersion {
		_, _ = fmt.Fprintln(stdout, "meiosisd "+version)
		return nil
	}
	if *principal == "" || *keyPath == "" {
		return fmt.Errorf("--principal and --key are required")
	}
	issuerFile, _, err := server.ResolveEnforcement(*issuerPubKeyPath, *dbPath, *allowUnauth, os.Stderr)
	if err != nil {
		return err
	}

	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	keys, err := crypto.LoadEncodedKeyPair(string(keyData), "")
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	backend, err := sqlite.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer func() { _ = backend.Close() }()

	server := mcp.NewServer(graph.NewStore(backend), *principal, keys.PrivateKey)

	if issuerFile != "" {
		pubKeyData, err := os.ReadFile(issuerFile)
		if err != nil {
			return fmt.Errorf("read issuer public key: %w", err)
		}
		issuerKey, err := crypto.LoadEncodedPublicKey(string(pubKeyData))
		if err != nil {
			return fmt.Errorf("load issuer public key: %w", err)
		}
		server.IssuerKey = issuerKey
		server.Revocation = identity.NewStoreRevocationList(backend)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *socketPath != "" {
		go func() {
			if err := serveSocket(ctx, server, *socketPath); err != nil {
				fmt.Fprintln(os.Stderr, "meiosisd: socket listener:", err)
			}
		}()
	}

	return server.Serve(ctx, stdin, stdout)
}

// serveSocket accepts connections on a UNIX domain socket at path, serving
// each one with the same JSON-RPC loop stdio uses — this is what satisfies
// the "listens cleanly over stdio or local socket" acceptance criterion
// without a second protocol implementation.
//
// ctx cancellation only interrupts a Server.Serve loop between scanned
// lines: a per-connection goroutine blocked reading from an idle conn won't
// notice ctx.Done() on its own. So beyond closing the listener, every
// accepted conn is tracked and force-closed on shutdown too — that unblocks
// its pending Read() and lets Serve return promptly instead of leaving the
// goroutine parked on a connection nobody will ever write to again.
func serveSocket(ctx context.Context, server *mcp.Server, path string) error {
	_ = os.Remove(path) // best-effort: clear a stale socket left by a prior run
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", path, err)
	}
	defer func() { _ = listener.Close() }()

	conns := &connSet{conns: make(map[net.Conn]struct{})}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		conns.closeAll()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		conns.add(conn)
		go func() {
			defer conns.remove(conn)
			defer func() { _ = conn.Close() }()
			_ = server.Serve(ctx, conn, conn)
		}()
	}
}
