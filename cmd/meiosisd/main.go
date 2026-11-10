// Command meiosisd is the long-running meiosis daemon. It serves the agent tools
// over MCP (stdio, a Unix socket or HTTP) against one repository, with
// capability enforcement on by default. `mei serve` runs the same code together
// with the Git server for a single-command first run. The implementation is in
// internal/daemon; this file only stamps the version and exits.
package main

import (
	"fmt"
	"os"

	"github.com/mindfire-test/meiosis/internal/daemon"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if err := daemon.Run(os.Args[1:], os.Stdin, os.Stdout, version); err != nil {
		fmt.Fprintln(os.Stderr, "meiosisd:", err)
		os.Exit(1)
	}
}
