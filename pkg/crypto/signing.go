package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// Sign canonicalizes value without its top-level signature field and signs the
// resulting RFC 8785 bytes with privateKey. The signature uses standard base64.
func Sign(value any, privateKey ed25519.PrivateKey) (string, error) {
	private, err := loadPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	canonical, err := unsignedCanonicalBytes(value)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical)), nil
}

// Verify checks a base64 Ed25519 signature against value's unsigned canonical
// representation and publicKey.
func Verify(value any, signature string, publicKey ed25519.PublicKey) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("%w: public key must be %d bytes", ErrInvalidKey, ed25519.PublicKeySize)
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("%w: decode signature: %w", ErrInvalidSignature, err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return false, fmt.Errorf("%w: signature must be %d bytes", ErrInvalidSignature, ed25519.SignatureSize)
	}
	canonical, err := unsignedCanonicalBytes(value)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, canonical, signatureBytes), nil
}

func unsignedCanonicalBytes(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", specv1.ErrUnsupportedCanonicalValue, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err == nil && fields != nil {
		delete(fields, "signature")
		data, err = json.Marshal(fields)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", specv1.ErrUnsupportedCanonicalValue, err)
		}
	}
	return specv1.CanonicalizeJSON(data)
}
