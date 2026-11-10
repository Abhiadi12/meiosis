// Command mei is the meiosis command line: it initialises a repository, drives
// intents, attempts, workspaces and evidence, serves Git, and runs backups. The
// commands live in internal/cli; this file only stamps the version and exits.
package main

import (
	"fmt"
	"os"

	"github.com/mindfire-test/meiosis/internal/cli"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	cli.Version = version
	if err := cli.New(nil).Execute(); err != nil {
		if !cli.IsSilent(err) {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
