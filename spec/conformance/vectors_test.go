package conformance_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/worlds"
)

// The known-answer vectors of SRS §4.3 and §11.4: canonical encodings,
// signatures, content-derived IDs and world hashes. They are language-agnostic
// JSON; verify_vectors.py checks the same files without any Go code.

func loadVectors(t *testing.T, name string, into any) {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestCanonicalEncodingVectors(t *testing.T) {
	var v struct {
		Cases []struct{ Name, Input, Canonical string }
	}
	loadVectors(t, "canonical.json", &v)
	if len(v.Cases) < 8 {
		t.Fatalf("only %d canonical vectors", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := specv1.CanonicalizeJSON([]byte(c.Input))
			if err != nil || string(got) != c.Canonical {
				t.Fatalf("CanonicalizeJSON =\n  %s\nwant\n  %s\n(%v)", got, c.Canonical, err)
			}
		})
	}
}

// The expected output of RFC 8785 §3.2.4, written out here from the RFC rather
// than read from the vectors file, so the file cannot quietly agree with a bug.
func TestRFC8785WorkedExample(t *testing.T) {
	in := `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/","literals":[null,true,false]}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := specv1.CanonicalizeJSON([]byte(in))
	if err != nil || string(got) != want {
		t.Fatalf("got  %s\nwant %s\n(%v)", got, want, err)
	}
}

func TestPropertyNameOrderIsByUTF16CodeUnit(t *testing.T) {
	// RFC 8785 §3.2.3: U+FB33 sorts after U+1F600 because the latter is the surrogate pair D83D DE00.
	got, err := specv1.CanonicalizeJSON([]byte(`{"דּ":3,"😀":2,"1":0,"€":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"1\":0,\"\u20ac\":1,\"\U0001F600\":2,\"\ufb33\":3}"; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestSignatureVectors(t *testing.T) {
	var v struct {
		SeedHex   string `json:"seed_hex"`
		PublicKey string `json:"public_key"`
		Cases     []struct {
			Name      string
			Object    json.RawMessage
			Canonical string `json:"canonical_unsigned"`
			Signature string
		}
	}
	loadVectors(t, "signatures.json", &v)
	seed, err := hex.DecodeString(v.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != v.PublicKey {
		t.Fatal("the vector's public key does not derive from its seed")
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			// Verify the stored signature with the public API...
			var obj map[string]any
			if err := json.Unmarshal(c.Object, &obj); err != nil {
				t.Fatal(err)
			}
			ok, err := crypto.Verify(obj, c.Signature, pub)
			if err != nil || !ok {
				t.Fatalf("Verify = %v, %v", ok, err)
			}
			// ...and re-derive it: Ed25519 is deterministic, so signing must reproduce it exactly.
			sig, err := crypto.Sign(obj, priv)
			if err != nil || sig != c.Signature {
				t.Fatalf("Sign = %q (%v), want %q", sig, err, c.Signature)
			}
			// Tampering with any byte of the object invalidates it.
			obj["x_tamper"] = true
			if ok, _ := crypto.Verify(obj, c.Signature, pub); ok {
				t.Fatal("a modified object still verified")
			}
		})
	}
}

func TestContentIDVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name, Prefix, Canonical, ID string
			Template                    json.RawMessage
		}
	}
	loadVectors(t, "content-ids.json", &v)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var obj any
			switch c.Prefix {
			case "int_":
				var i specv1.Intent
				if err := json.Unmarshal(c.Template, &i); err != nil {
					t.Fatal(err)
				}
				obj = i
			case "evd_":
				var e specv1.Evidence
				if err := json.Unmarshal(c.Template, &e); err != nil {
					t.Fatal(err)
				}
				obj = e
			}
			canonical, err := specv1.Canonicalize(obj)
			if err != nil || string(canonical) != c.Canonical {
				t.Fatalf("canonical form = %s (%v), want %s", canonical, err, c.Canonical)
			}
			id, err := specv1.NewContentID(c.Prefix, obj)
			if err != nil || id != c.ID {
				t.Fatalf("NewContentID = %q (%v), want %q", id, err, c.ID)
			}
		})
	}
}

func TestWorldHashVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name  string
			World string
			Files []struct {
				Path          string
				ContentBase64 string `json:"content_base64"`
			}
		}
	}
	loadVectors(t, "world-hashes.json", &v)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			files := map[string][]byte{}
			for _, f := range c.Files {
				content, err := base64.StdEncoding.DecodeString(f.ContentBase64)
				if err != nil {
					t.Fatal(err)
				}
				files[f.Path] = content
			}
			tree, err := worlds.NewMemoryTree(files)
			if err != nil {
				t.Fatal(err)
			}
			w, err := worlds.New(context.Background(), tree)
			if err != nil || w.Hash().String() != c.World {
				t.Fatalf("world = %s (%v), want %s", w.Hash(), err, c.World)
			}
		})
	}
}
