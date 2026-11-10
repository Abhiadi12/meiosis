package graph

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/zeebo/blake3"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// PinDigest returns the lower-case hex BLAKE3-256 digest of content: the
// digest recorded in a ContextPin (FR-3.5).
func PinDigest(content []byte) string {
	sum := blake3.Sum256(content)
	return specv1.DigestHex(sum)
}

// NewContextPin pins the document ref as it was consumed, recording the digest
// of content.
func NewContextPin(ref string, kind specv1.ContextPinKind, content []byte) (specv1.ContextPin, error) {
	if strings.TrimSpace(ref) == "" {
		return specv1.ContextPin{}, fmt.Errorf("%w: pin ref must not be empty", ErrInvalidParams)
	}
	pin := specv1.ContextPin{Ref: ref, Digest: PinDigest(content), Kind: kind}
	switch kind {
	case specv1.ContextPinKindSpec, specv1.ContextPinKindADR, specv1.ContextPinKindIssue, specv1.ContextPinKindDesign, specv1.ContextPinKindConvention:
	default:
		return specv1.ContextPin{}, fmt.Errorf("%w: unknown pin kind %q", ErrInvalidParams, kind)
	}
	return pin, nil
}

// Pin check outcomes.
const (
	PinMatch     = "match"     // the document still has the pinned digest
	PinChanged   = "changed"   // the document's content differs from the pin
	PinMissing   = "missing"   // the pinned file no longer exists
	PinUnchecked = "unchecked" // the ref is not a local file (URL, issue id): cannot be checked here
)

// PinCheck is the result of re-reading one pinned document.
type PinCheck struct {
	Ref    string `json:"ref"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Pinned string `json:"pinned_digest"`
	// Current is the digest of the document now; empty unless it was read.
	Current string `json:"current_digest,omitempty"`
}

// Stale reports whether the pin shows its document has changed, which is what
// makes dependent attempts stale (FR-3.6, enforced in M2).
func (c PinCheck) Stale() bool { return c.Status == PinChanged || c.Status == PinMissing }

// VerifyPins re-reads every pinned document that is a file under root and
// compares its digest with the pin. Refs that are URLs or otherwise not
// repo-relative paths are reported as unchecked rather than guessed at.
func VerifyPins(root string, pins []specv1.ContextPin) []PinCheck {
	checks := make([]PinCheck, 0, len(pins))
	for _, pin := range pins {
		check := PinCheck{Ref: pin.Ref, Kind: string(pin.Kind), Pinned: pin.Digest, Status: PinUnchecked}
		if full, ok := localPath(root, pin.Ref); ok {
			content, err := os.ReadFile(full)
			switch {
			case errors.Is(err, os.ErrNotExist):
				check.Status = PinMissing
			case err != nil:
				check.Status = PinUnchecked
			default:
				check.Current = PinDigest(content)
				if check.Current == pin.Digest {
					check.Status = PinMatch
				} else {
					check.Status = PinChanged
				}
			}
		}
		checks = append(checks, check)
	}
	return checks
}

// localPath maps a pin ref to a file under root, if it is a plain
// repo-relative path that stays inside root.
func localPath(root, ref string) (string, bool) {
	if ref == "" || strings.Contains(ref, "://") || strings.HasPrefix(ref, "#") || strings.ContainsRune(ref, '\\') {
		return "", false
	}
	clean := path.Clean(ref)
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
		return "", false
	}
	return filepath.Join(root, filepath.FromSlash(clean)), true
}
