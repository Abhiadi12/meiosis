package v1

// NewContentID returns "<prefix><base32(blake3(canonical json of value))>",
// the content-derived ID form documented for Intent/Attempt IDs (unlike
// CapabilityToken's random ID — see internal/identity's newTokenID comment
// for why the two schemes differ: a content ID means two objects with
// identical fields always collide onto the same ID, which is exactly what a
// random ID must avoid).
//
// Callers must zero any ID and Signature field on value before calling, so
// the ID is derived from the object's actual content rather than from
// whatever placeholder was in those fields.
func NewContentID(prefix string, value any) (string, error) {
	digest, err := HashCanonical(value)
	if err != nil {
		return "", err
	}
	return prefix + identifierEncoding.EncodeToString(digest[:]), nil
}
