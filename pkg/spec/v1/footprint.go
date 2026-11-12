package v1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// MaxFootprintEntries caps the entries in one footprint, so a single evidence
// record cannot make every later standing computation expensive.
const MaxFootprintEntries = 1000

// SymbolFootprintPrefix marks a symbol footprint entry (sym:pkg.Name). The form
// is reserved: it is rejected until symbol analysis exists, so no evidence is
// accepted with a footprint that cannot be honoured.
const SymbolFootprintPrefix = "sym:"

// ParseFootprint validates and normalises an evidence footprint: the paths and
// globs the evidence depends on. Each entry must be a clean repository path
// (ValidRepoPath) and a valid doublestar pattern; symbol entries are refused.
//
// The result is sorted and de-duplicated, and an exact path matched by a glob
// in the same footprint is dropped (a/b.go next to a/** adds nothing), so two
// footprints with the same meaning normalise to the same entries and therefore
// sign to the same bytes. Globs are kept even when another glob covers them:
// dropping them would need pattern containment, and keeping an extra entry is
// always safe.
//
// An empty footprint is valid and means "the whole world"; it returns nil so
// the field stays omitted when the evidence is encoded.
func ParseFootprint(entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > MaxFootprintEntries {
		return nil, fmt.Errorf("%w: %d entries, at most %d are allowed", ErrInvalidFootprint, len(entries), MaxFootprintEntries)
	}

	seen := make(map[string]bool, len(entries))
	var globs, paths []string
	for i, entry := range entries {
		if err := checkFootprintEntry(entry); err != nil {
			return nil, fmt.Errorf("%w: entry %d %q: %s", ErrInvalidFootprint, i, entry, err)
		}
		if seen[entry] {
			continue
		}
		seen[entry] = true
		if isFootprintGlob(entry) {
			globs = append(globs, entry)
		} else {
			paths = append(paths, entry)
		}
	}

	out := make([]string, 0, len(globs)+len(paths))
	out = append(out, globs...)
	for _, p := range paths {
		if !matchesAnyGlob(globs, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// checkFootprintEntry returns a short reason when entry is not acceptable.
func checkFootprintEntry(entry string) error {
	switch {
	case strings.HasPrefix(entry, SymbolFootprintPrefix):
		return fmt.Errorf("symbol footprints are reserved for a later version; list the files or globs instead")
	case !ValidRepoPath(entry):
		return fmt.Errorf("must be a clean, relative, slash-separated path inside the repository")
	case !doublestar.ValidatePattern(entry):
		return fmt.Errorf("is not a valid glob pattern")
	}
	return nil
}

// isFootprintGlob reports whether entry uses doublestar pattern syntax.
// Backslash escapes cannot occur: ValidRepoPath rejects them.
func isFootprintGlob(entry string) bool {
	return strings.ContainsAny(entry, "*?[{")
}

func matchesAnyGlob(globs []string, path string) bool {
	for _, g := range globs {
		if ok, err := doublestar.Match(g, path); err == nil && ok {
			return true
		}
	}
	return false
}
