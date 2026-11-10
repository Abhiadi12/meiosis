package v1

import (
	"encoding/base32"
	"path"
	"strings"
)

var identifierEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func validContentID(value, prefix string) bool {
	if len(value) != len(prefix)+52 || value[:len(prefix)] != prefix {
		return false
	}
	_, err := identifierEncoding.DecodeString(value[len(prefix):])
	return err == nil
}

// ValidRepoPath reports whether p is a safe repository-relative path: slash
// separated, relative, already clean, and not escaping the root. It is the one
// definition used for worlds, scopes and workspace writes.
func ValidRepoPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	clean := path.Clean(p)
	return clean == p && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}
