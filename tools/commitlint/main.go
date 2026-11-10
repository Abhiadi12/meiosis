// Command commitlint checks commit messages against the project's Conventional
// Commits rules (the Go replacement for the npm commitlint the repo used to
// need; the rules mirror .commitlintrc.yaml).
//
//	commitlint FILE               check the message in FILE (the commit-msg hook)
//	commitlint --from A --to B    check every commit in the range A..B (CI)
//
// It has no dependencies beyond the standard library and git.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var types = []string{"build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test"}

const (
	maxHeader = 100
	maxBody   = 200
)

var header = regexp.MustCompile(`^(` + strings.Join(types, "|") + `)(!?)\(([a-z0-9][a-z0-9_./-]*)\)(!?): (.+)$`)

// Lint returns every rule the message breaks; none means it is acceptable.
func Lint(msg string) []string {
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(msg, "\n"), "\n")
	first := strings.TrimSpace(lines[0])
	if strings.HasPrefix(first, "Merge ") || strings.HasPrefix(first, "Revert \"") || strings.HasPrefix(first, "fixup! ") || strings.HasPrefix(first, "squash! ") {
		return nil
	}
	var problems []string
	m := header.FindStringSubmatch(first)
	if m == nil {
		problems = append(problems, "header must be `<type>(<scope>): <subject>` with a scope; types: "+strings.Join(types, ", "))
	} else {
		subject := m[5]
		if strings.HasSuffix(subject, ".") {
			problems = append(problems, "subject must not end with a full stop")
		}
		if r := subject[0]; r >= 'A' && r <= 'Z' {
			problems = append(problems, "subject must start in lower case")
		}
	}
	if len(first) > maxHeader {
		problems = append(problems, fmt.Sprintf("header is %d characters, the limit is %d", len(first), maxHeader))
	}
	if len(lines) > 1 && strings.TrimSpace(lines[1]) != "" {
		problems = append(problems, "leave a blank line between header and body")
	}
	for i, l := range lines[1:] {
		// URLs and trailers cannot be wrapped.
		if len(l) > maxBody && !strings.Contains(l, "://") {
			problems = append(problems, fmt.Sprintf("body line %d is %d characters, the limit is %d", i+2, len(l), maxBody))
		}
	}
	return problems
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	return string(out), err
}

func main() {
	from := flag.String("from", "", "first commit (exclusive) of the range to check")
	to := flag.String("to", "HEAD", "last commit of the range to check")
	flag.Parse()

	failed := 0
	report := func(label, msg string) {
		if p := Lint(msg); len(p) > 0 {
			failed++
			fmt.Fprintf(os.Stderr, "✗ %s\n", label)
			for _, line := range p {
				fmt.Fprintf(os.Stderr, "    - %s\n", line)
			}
		}
	}

	switch {
	case *from != "":
		revs, err := git("rev-list", "--no-merges", "--reverse", *from+".."+*to)
		if err != nil {
			fmt.Fprintln(os.Stderr, "commitlint: git rev-list:", err)
			os.Exit(2)
		}
		for _, rev := range strings.Fields(revs) {
			msg, err := git("log", "-1", "--format=%B", rev)
			if err != nil {
				fmt.Fprintln(os.Stderr, "commitlint: git log:", err)
				os.Exit(2)
			}
			report(rev[:min(8, len(rev))]+" "+strings.SplitN(msg, "\n", 2)[0], msg)
		}
	case flag.NArg() == 1:
		data, err := os.ReadFile(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "commitlint:", err)
			os.Exit(2)
		}
		// git strips comment lines before committing; do the same.
		var kept []string
		for _, l := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(l, "#") {
				kept = append(kept, l)
			}
		}
		msg := strings.Join(kept, "\n")
		report(strings.SplitN(strings.TrimSpace(msg), "\n", 2)[0], msg)
	default:
		fmt.Fprintln(os.Stderr, "usage: commitlint FILE | commitlint --from REV [--to REV]")
		os.Exit(2)
	}
	if failed > 0 {
		fmt.Fprintln(os.Stderr, "\nExpected: feat(api): add the authentication endpoint")
		os.Exit(1)
	}
}
