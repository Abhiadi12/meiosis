package crypto

import (
	"crypto/ed25519"
	"testing"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

func TestGenerateAndLoadKeyPair(t *testing.T) {
	original, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if len(original.PublicKey) != ed25519.PublicKeySize || len(original.PrivateKey) != ed25519.PrivateKeySize {
		t.Fatal("GenerateKeyPair() returned incorrectly sized keys")
	}
	loaded, err := LoadKeyPair(original.PrivateKey, original.PublicKey)
	if err != nil {
		t.Fatalf("LoadKeyPair() error = %v", err)
	}
	if loaded.PublicKeyBase64() != original.PublicKeyBase64() || loaded.PrivateKeyBase64() != original.PrivateKeyBase64() {
		t.Fatal("LoadKeyPair() changed key material")
	}
}

func TestLoadKeyPairRejectsMalformedKeys(t *testing.T) {
	valid, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	for name, privateKey := range map[string][]byte{
		"empty": nil, "short": make([]byte, ed25519.SeedSize-1),
		"malformed": make([]byte, ed25519.PrivateKeySize), "long": make([]byte, ed25519.PrivateKeySize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadKeyPair(privateKey, nil); err == nil {
				t.Fatal("LoadKeyPair() accepted malformed private key")
			}
		})
	}
	if _, err := LoadKeyPair(valid.PrivateKey, make([]byte, ed25519.PublicKeySize)); err == nil {
		t.Fatal("LoadKeyPair() accepted mismatched public key")
	}
}

func TestSignAndVerifyCanonicalObject(t *testing.T) {
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	object := map[string]any{"id": "agent:planner-7", "kind": "agent"}
	signature, err := Sign(object, keys.PrivateKey)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	valid, err := Verify(map[string]any{"kind": "agent", "id": "agent:planner-7"}, signature, keys.PublicKey)
	if err != nil || !valid {
		t.Fatalf("Verify() = %v, %v", valid, err)
	}
	if repeated, _ := Sign(object, keys.PrivateKey); signature != repeated {
		t.Fatal("Sign() was not deterministic")
	}
	if valid, err := Verify(map[string]any{"id": "agent:other", "kind": "agent"}, signature, keys.PublicKey); err != nil || valid {
		t.Fatalf("Verify() accepted changed object: %v, %v", valid, err)
	}
}

func TestVerifyRejectsInvalidSignature(t *testing.T) {
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if _, err := Verify(specv1.Principal{ID: "agent:planner-7", Kind: specv1.PrincipalKindAgent}, "not-base64", keys.PublicKey); err == nil {
		t.Fatal("Verify() accepted malformed signature")
	}
	if _, err := Sign(specv1.Principal{ID: "agent:planner-7", Kind: specv1.PrincipalKindAgent}, make(ed25519.PrivateKey, ed25519.SeedSize-1)); err == nil {
		t.Fatal("Sign() accepted malformed private key")
	}
}
