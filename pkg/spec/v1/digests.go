package v1

import (
	"encoding/hex"
	"strings"

	"github.com/zeebo/blake3"
)

// BLAKE3DigestSize is the size in bytes of every BLAKE3 digest used by the format.
const BLAKE3DigestSize = 32

// HashCanonical returns the BLAKE3-256 digest of value's RFC 8785 canonical
// JSON representation.
func HashCanonical(value any) ([BLAKE3DigestSize]byte, error) {
	canonical, err := Canonicalize(value)
	if err != nil {
		return [BLAKE3DigestSize]byte{}, err
	}
	return blake3.Sum256(canonical), nil
}

// HashCanonicalJSON returns the BLAKE3-256 digest of canonical JSON input.
func HashCanonicalJSON(data []byte) ([BLAKE3DigestSize]byte, error) {
	canonical, err := CanonicalizeJSON(data)
	if err != nil {
		return [BLAKE3DigestSize]byte{}, err
	}
	return blake3.Sum256(canonical), nil
}

// DigestHex returns a lower-case hexadecimal representation of a digest.
func DigestHex(digest [BLAKE3DigestSize]byte) string {
	return hex.EncodeToString(digest[:])
}

func validHexDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
