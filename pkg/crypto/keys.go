// Package crypto holds the Ed25519 key handling and signing used across
// meiosis: PEM key files, and signatures over the RFC 8785 canonical form of any
// spec/v1 object. It has no dependency on the rest of the implementation, so a
// second implementation can reproduce it from the spec alone.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// KeyPair contains an Ed25519 private key and its corresponding public key.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair creates a new cryptographically secure Ed25519 keypair.
func GenerateKeyPair() (KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate Ed25519 keypair: %w", err)
	}
	return KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// LoadKeyPair loads raw Ed25519 key material. privateKey may be either a
// 32-byte seed or a 64-byte private key. If publicKey is nil, it is derived.
func LoadKeyPair(privateKey, publicKey []byte) (KeyPair, error) {
	private, err := loadPrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, err
	}
	public := append(ed25519.PublicKey(nil), private[ed25519.SeedSize:]...)
	if publicKey != nil {
		if len(publicKey) != ed25519.PublicKeySize {
			return KeyPair{}, fmt.Errorf("%w: public key must be %d bytes", ErrInvalidKey, ed25519.PublicKeySize)
		}
		if subtle.ConstantTimeCompare(public, publicKey) != 1 {
			return KeyPair{}, ErrKeyMismatch
		}
	}
	return KeyPair{PublicKey: public, PrivateKey: private}, nil
}

// LoadEncodedKeyPair loads raw base64 or PEM-encoded Ed25519 key material.
// Private keys may be PKCS#8 PEM; public keys may be PKIX PEM.
func LoadEncodedKeyPair(privateKey, publicKey string) (KeyPair, error) {
	private, err := decodePrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, err
	}
	var public []byte
	if publicKey != "" {
		public, err = decodePublicKey(publicKey)
		if err != nil {
			return KeyPair{}, err
		}
	}
	return LoadKeyPair(private, public)
}

// LoadEncodedPublicKey loads a base64 or PEM-encoded (PKIX) Ed25519 public
// key, e.g. one written out for a daemon that only needs to verify tokens
// signed by an issuer it doesn't hold the private key for.
func LoadEncodedPublicKey(publicKey string) (ed25519.PublicKey, error) {
	data, err := decodePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be %d bytes", ErrInvalidKey, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(data), nil
}

func (k KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(k.PublicKey)
}

func (k KeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(k.PrivateKey)
}

func loadPrivateKey(data []byte) (ed25519.PrivateKey, error) {
	switch len(data) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(data), nil
	case ed25519.PrivateKeySize:
		private := append(ed25519.PrivateKey(nil), data...)
		derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(derived, private) != 1 {
			return nil, ErrKeyMismatch
		}
		return private, nil
	default:
		return nil, fmt.Errorf("%w: private key must be %d-byte seed or %d-byte key", ErrInvalidKey, ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func decodePrivateKey(value string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(value)); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse private key PEM: %w", ErrInvalidKey, err)
		}
		private, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: PEM key is not Ed25519", ErrInvalidKey)
		}
		return private, nil
	}
	return decodeBase64Key(value, "private")
}

func decodePublicKey(value string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(value)); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse public key PEM: %w", ErrInvalidKey, err)
		}
		public, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: PEM key is not Ed25519", ErrInvalidKey)
		}
		return public, nil
	}
	return decodeBase64Key(value, "public")
}

func decodeBase64Key(value, kind string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: decode %s key: %w", ErrInvalidKey, kind, err)
	}
	return data, nil
}
