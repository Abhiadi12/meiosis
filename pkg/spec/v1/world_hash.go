package v1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// WorldHashSize is the size in bytes of a WorldHash.
const WorldHashSize = 32

// WorldHash is the canonical 32-byte content hash for a tree/world state.
type WorldHash [WorldHashSize]byte

// ParseWorldHash parses the 64-character hexadecimal form of a world hash.
func ParseWorldHash(s string) (WorldHash, error) {
	var h WorldHash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != WorldHashSize {
		return h, ErrInvalidWorldHash
	}
	copy(h[:], b)
	return h, nil
}

// MustParseWorldHash is ParseWorldHash for constants and tests; it panics on bad input.
func MustParseWorldHash(s string) WorldHash {
	h, err := ParseWorldHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

// Short is the first 12 hex digits, for display. It is not unique.
func (h WorldHash) Short() string { return h.String()[:12] }

func (h WorldHash) String() string {
	return hex.EncodeToString(h[:])
}

// Validate reports whether the hash is non-zero.
func (h WorldHash) Validate() error {
	if h == (WorldHash{}) {
		return ErrInvalidWorldHash
	}
	return nil
}

// MarshalJSON encodes the hash as its hexadecimal string.
func (h WorldHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

// UnmarshalJSON decodes the hexadecimal string form.
func (h *WorldHash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("%w: expected string", ErrInvalidWorldHash)
	}
	parsed, err := ParseWorldHash(s)
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}
