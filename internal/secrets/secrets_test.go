package secrets

import (
	"strings"
	"testing"
)

// The fake credentials are assembled from parts so this file does not itself
// contain a string a secret scanner would flag.
func fake(parts ...string) string { return strings.Join(parts, "") }

func rulesOf(fs []Finding) map[string]Confidence {
	m := map[string]Confidence{}
	for _, f := range fs {
		m[f.Rule] = f.Confidence
	}
	return m
}

func TestScanLineRecognisesCommonCredentials(t *testing.T) {
	for name, c := range map[string]struct {
		line, rule string
		conf       Confidence
	}{
		"pem":          {fake("-----BEGIN RSA ", "PRIVATE KEY-----"), "private-key-block", High},
		"openssh":      {fake("-----BEGIN OPENSSH ", "PRIVATE KEY-----"), "private-key-block", High},
		"aws":          {`aws_key = "` + fake("AKIA", "IOSFODNN7EXAMPLE") + `"`, "aws-access-key-id", High},
		"github":       {"token: " + fake("ghp_", strings.Repeat("a1B2", 9)), "github-token", High},
		"fine-grained": {fake("github_pat_", strings.Repeat("x", 60)), "github-token", High},
		"slack":        {fake("xoxb-", "123456789012-abcdefghij"), "slack-token", High},
		"google":       {fake("AIza", strings.Repeat("a", 35)), "google-api-key", High},
		"stripe":       {fake("sk_", "live_", strings.Repeat("9", 24)), "stripe-live-key", High},
		"llm":          {fake("sk-", "ant-", strings.Repeat("z", 30)), "llm-api-key", High},
		"assigned":     {`password = "` + strings.Repeat("a1", 15) + `"`, "generic-secret-assignment", Possible},
	} {
		got := rulesOf(ScanLine(c.line))
		if got[c.rule] != c.conf {
			t.Errorf("%s: rules = %v, want %s (%s)", name, got, c.rule, c.conf)
		}
	}
}

func TestScanLineLeavesOrdinaryCodeAlone(t *testing.T) {
	for _, line := range []string{
		"func main() { fmt.Println(\"hello\") }",
		"password := os.Getenv(\"PASSWORD\")",
		`token = "short"`,
		"// AKIA is a prefix",
		"const keyLength = 4096",
		"see https://example.com/docs/api-key-rotation",
		"-----BEGIN CERTIFICATE-----",
		"",
	} {
		if got := ScanLine(line); len(got) != 0 {
			t.Errorf("%q flagged: %v", line, got)
		}
	}
}

func TestFindingsNameTheRuleNeverTheSecret(t *testing.T) {
	secret := fake("ghp_", strings.Repeat("Q9", 20))
	for _, f := range ScanLine("x := \"" + secret + "\"") {
		for _, field := range []string{f.Path, f.Rule, string(f.Confidence)} {
			if strings.Contains(field, secret) {
				t.Fatalf("a finding carries the secret: %+v", f)
			}
		}
	}
}

func TestVeryLongLinesAreOnlyExaminedInPart(t *testing.T) {
	long := strings.Repeat("a", maxLine+10) + fake("AKIA", "IOSFODNN7EXAMPLE")
	if got := ScanLine(long); len(got) != 0 {
		t.Fatalf("a credential past the limit was still scanned: %v", got)
	}
}

func TestScanPath(t *testing.T) {
	for p, want := range map[string]string{
		".meiosis/human.private.key": "meiosis-private-state",
		"deploy/ci.private.key":      "private-key-file",
		"home/.ssh/id_ed25519":       "ssh-private-key-file",
		".env":                       "dotenv-file",
		"app/.env.production":        "dotenv-file",
		"certs/server.pem":           "certificate-or-key-file",
		"src/main.go":                "",
		".env.example":               "",
		"docs/env.md":                "",
	} {
		got := ""
		if fs := ScanPath(p); len(fs) > 0 {
			got = fs[0].Rule
		}
		if got != want {
			t.Errorf("ScanPath(%q) = %q, want %q", p, got, want)
		}
	}
	if fs := ScanPath("certs/server.pem"); fs[0].Confidence != Possible {
		t.Error("a .pem file may be a public certificate: it must not block")
	}
	if fs := ScanPath(".meiosis/x"); fs[0].Confidence != High {
		t.Error("meiosis private state is always a mistake to push")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeWarn, "warn": ModeWarn, " BLOCK ": ModeBlock, "off": ModeOff} {
		if got, ok := ParseMode(in); !ok || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := ParseMode("loud"); ok {
		t.Error("an unknown mode was accepted")
	}
}
