// Package textdiff renders a unified diff of two texts. It is deliberately
// small: line-based, longest-common-subsequence, with hard limits so a huge or
// binary file produces a one-line note instead of a slow or enormous answer.
// Meiosis shows diffs to people and agents reviewing a workspace; it does not
// need to produce patches for `patch` to apply.
package textdiff

import (
	"bytes"
	"fmt"
	"strings"
)

// Limits on what is diffed in line detail.
const (
	// MaxBytes is the largest file (either side) that gets a line diff.
	MaxBytes = 256 << 10
	// MaxMiddleLines caps the lines left after trimming the unchanged head and
	// tail of each side; the LCS table is the square of this.
	MaxMiddleLines = 2000
)

// IsBinary reports whether data looks like binary content.
func IsBinary(data []byte) bool {
	n := min(len(data), 8000)
	return bytes.IndexByte(data[:n], 0) >= 0
}

// Unified returns a unified diff of before to after, labelled with name, with
// the given lines of context. An empty string means the texts are identical.
// Content that is binary or too large yields a single explanatory line.
func Unified(name string, before, after []byte, context int) string {
	if bytes.Equal(before, after) {
		return ""
	}
	if IsBinary(before) || IsBinary(after) {
		return fmt.Sprintf("Binary files a/%s and b/%s differ\n", name, name)
	}
	if len(before) > MaxBytes || len(after) > MaxBytes {
		return fmt.Sprintf("File a/%s -> b/%s is too large to diff inline (%d -> %d bytes)\n", name, name, len(before), len(after))
	}
	a, b := splitLines(before), splitLines(after)

	// Trim the common head and tail: edits are usually local.
	head := 0
	for head < len(a) && head < len(b) && a[head] == b[head] {
		head++
	}
	tail := 0
	for tail < len(a)-head && tail < len(b)-head && a[len(a)-1-tail] == b[len(b)-1-tail] {
		tail++
	}
	ma, mb := a[head:len(a)-tail], b[head:len(b)-tail]
	if len(ma) > MaxMiddleLines || len(mb) > MaxMiddleLines {
		return fmt.Sprintf("File a/%s -> b/%s changed too much to diff inline (%d -> %d lines)\n", name, name, len(a), len(b))
	}

	edits := make([]edit, 0, len(a)+len(b))
	for i := 0; i < head; i++ {
		edits = append(edits, edit{op: ' ', text: a[i]})
	}
	edits = append(edits, lcsEdits(ma, mb)...)
	for i := len(a) - tail; i < len(a); i++ {
		edits = append(edits, edit{op: ' ', text: a[i]})
	}
	return render(name, edits, context)
}

type edit struct {
	op   byte // ' ', '-', '+'
	text string
}

// splitLines splits keeping a marker for a missing final newline, so a change
// only to the last line's newline shows as a change.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	s := string(data)
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	} else {
		lines[len(lines)-1] += "\n\\ No newline at end of file\n"
	}
	return lines
}

func lcsEdits(a, b []string) []edit {
	n, m := len(a), len(b)
	if n == 0 {
		out := make([]edit, m)
		for i, t := range b {
			out[i] = edit{'+', t}
		}
		return out
	}
	if m == 0 {
		out := make([]edit, n)
		for i, t := range a {
			out[i] = edit{'-', t}
		}
		return out
	}
	// table[i][j] = length of the LCS of a[i:] and b[j:].
	table := make([][]uint16, n+1)
	for i := range table {
		table[i] = make([]uint16, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else {
				table[i][j] = max(table[i+1][j], table[i][j+1])
			}
		}
	}
	var out []edit
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, edit{' ', a[i]})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			out = append(out, edit{'-', a[i]})
			i++
		default:
			out = append(out, edit{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, edit{'-', a[i]})
	}
	for ; j < m; j++ {
		out = append(out, edit{'+', b[j]})
	}
	return out
}

func render(name string, edits []edit, context int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n", name, name)

	// Find ranges of edits that are changes, widen by context, merge overlaps.
	type span struct{ from, to int } // half-open, indexes into edits
	var spans []span
	for i, e := range edits {
		if e.op == ' ' {
			continue
		}
		from, to := max(0, i-context), min(len(edits), i+context+1)
		if n := len(spans); n > 0 && from <= spans[n-1].to {
			spans[n-1].to = max(spans[n-1].to, to)
		} else {
			spans = append(spans, span{from, to})
		}
	}

	// Line numbers at the start of each edit.
	aLine, bLine := make([]int, len(edits)+1), make([]int, len(edits)+1)
	a, b := 1, 1
	for i, e := range edits {
		aLine[i], bLine[i] = a, b
		if e.op != '+' {
			a++
		}
		if e.op != '-' {
			b++
		}
	}
	aLine[len(edits)], bLine[len(edits)] = a, b

	for _, sp := range spans {
		aCount, bCount := 0, 0
		for _, e := range edits[sp.from:sp.to] {
			if e.op != '+' {
				aCount++
			}
			if e.op != '-' {
				bCount++
			}
		}
		aStart, bStart := aLine[sp.from], bLine[sp.from]
		if aCount == 0 {
			aStart--
		}
		if bCount == 0 {
			bStart--
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", aStart, aCount, bStart, bCount)
		for _, e := range edits[sp.from:sp.to] {
			sb.WriteByte(e.op)
			sb.WriteString(e.text)
			if !strings.HasSuffix(e.text, "\n") {
				sb.WriteByte('\n')
			}
		}
	}
	return sb.String()
}
