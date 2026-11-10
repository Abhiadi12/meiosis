// Package secrets looks for credentials in code that is about to be pushed
// (NFR-4.4). It is a tripwire for the common, recognisable cases (private key
// blocks, cloud and source-host tokens), not a guarantee: an unrecognised secret
// passes. A finding names where it is and which rule matched, never the secret
// itself, so reporting one cannot spread it.
package secrets

import (
	"path"
	"regexp"
	"strings"
)

// Confidence says how sure a rule is.
type Confidence string

const (
	// High rules match a fixed, distinctive format; a match is almost certainly
	// a credential. These are the ones a repository may choose to block on.
	High Confidence = "high"
	// Possible rules look for the shape of a secret (a long literal assigned to
	// something named "secret" or "token") and have false positives. They are
	// reported but never block.
	Possible Confidence = "possible"
)

// Finding is one match.
type Finding struct {
	Path       string     `json:"path"`
	Line       int        `json:"line,omitempty"` // 0 for a finding about the path itself
	Rule       string     `json:"rule"`
	Confidence Confidence `json:"confidence"`
}

type rule struct {
	name       string
	confidence Confidence
	re         *regexp.Regexp
}

var rules = []rule{
	{"private-key-block", High, regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	{"aws-access-key-id", High, regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"github-token", High, regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`)},
	{"slack-token", High, regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{"google-api-key", High, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"stripe-live-key", High, regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}\b`)},
	{"llm-api-key", High, regexp.MustCompile(`\bsk-(?:ant|proj)-[A-Za-z0-9_-]{20,}\b`)},
	{"generic-secret-assignment", Possible, regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|passwd|password|token|auth)[A-Za-z0-9_-]*\s*[:=]\s*["'][A-Za-z0-9/+_=-]{20,}["']`)},
}

// maxLine bounds how much of one line is examined: minified bundles are not
// where credentials hide, and a regex over megabytes is a cost.
const maxLine = 4096

// ScanLine returns the rules a line of source matches.
func ScanLine(line string) []Finding {
	if len(line) > maxLine {
		line = line[:maxLine]
	}
	var out []Finding
	for _, r := range rules {
		if r.re.MatchString(line) {
			out = append(out, Finding{Rule: r.name, Confidence: r.confidence})
		}
	}
	return out
}

// ScanPath returns findings about a file by its name: credential files that
// should not be in a repository at all, whatever they contain.
func ScanPath(p string) []Finding {
	base := path.Base(p)
	var rule string
	switch {
	case strings.HasPrefix(p, ".meiosis/") || strings.Contains(p, "/.meiosis/"):
		rule = "meiosis-private-state"
	case strings.HasSuffix(base, ".private.key"):
		rule = "private-key-file"
	case base == "id_rsa" || base == "id_ed25519" || base == "id_ecdsa" || base == "id_dsa":
		rule = "ssh-private-key-file"
	case base == ".env" || strings.HasPrefix(base, ".env."):
		if base == ".env.example" || base == ".env.sample" || base == ".env.template" {
			return nil
		}
		rule = "dotenv-file"
	case strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx"):
		rule = "certificate-or-key-file"
	default:
		return nil
	}
	c := High
	if rule == "certificate-or-key-file" || rule == "dotenv-file" {
		c = Possible // a .pem may be a public certificate; a .env may hold nothing secret
	}
	return []Finding{{Path: p, Rule: rule, Confidence: c}}
}

// Mode is what a repository does with findings.
type Mode string

const (
	ModeOff   Mode = "off"
	ModeWarn  Mode = "warn"
	ModeBlock Mode = "block"
)

// ParseMode validates a configured mode; empty means warn.
func ParseMode(s string) (Mode, bool) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "":
		return ModeWarn, true
	case ModeOff:
		return ModeOff, true
	case ModeWarn:
		return ModeWarn, true
	case ModeBlock:
		return ModeBlock, true
	}
	return "", false
}
