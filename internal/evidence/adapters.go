// Package evidence turns the reports verification tools already produce (JUnit
// XML, go test -json, SARIF, Cobertura, LCOV, CycloneDX) into signed evidence
// records bound to a world hash (FR-4.3).
//
// The adapters only read: meiosis executes nothing (SRS §2.2). A report is
// parsed into a summary payload and an outcome; the verdict about whether that
// outcome is good enough belongs to policy, not to the adapter.
package evidence

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

// Format names a report format an adapter understands.
type Format string

// Format names the report formats the adapters understand.
const (
	FormatGoTest    Format = "gotest"
	FormatJUnit     Format = "junit"
	FormatSARIF     Format = "sarif"
	FormatCobertura Format = "cobertura"
	FormatLCOV      Format = "lcov"
	FormatCycloneDX Format = "cyclonedx"
)

// MaxReportBytes bounds the size of a report an adapter will read.
const MaxReportBytes = 32 << 20

// maxXMLDepth bounds element nesting in XML reports. encoding/xml decodes
// nested elements recursively, so unbounded nesting in untrusted input could
// exhaust the stack.
const maxXMLDepth = 64

// ErrUnsupported is returned for a format or kind combination the adapters do
// not handle.
var ErrUnsupported = errors.New("evidence: unsupported report")

// Formats lists every format with an adapter, sorted.
func Formats() []Format {
	f := []Format{FormatGoTest, FormatJUnit, FormatSARIF, FormatCobertura, FormatLCOV, FormatCycloneDX}
	sort.Slice(f, func(i, j int) bool { return f[i] < f[j] })
	return f
}

// ParseFormat validates a user-supplied format name.
func ParseFormat(name string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(name)))
	for _, known := range Formats() {
		if f == known {
			return f, nil
		}
	}
	return "", fmt.Errorf("%w: unknown format %q (known: %v)", ErrUnsupported, name, Formats())
}

// DefaultKind is the evidence kind a format produces unless overridden.
func DefaultKind(f Format) specv1.EvidenceKind {
	switch f {
	case FormatGoTest, FormatJUnit:
		return specv1.EvidenceKindTestRun
	case FormatSARIF:
		return specv1.EvidenceKindStaticAnalysis
	case FormatCobertura, FormatLCOV:
		return specv1.EvidenceKindCoverage
	case FormatCycloneDX:
		return specv1.EvidenceKindSecurityScan
	}
	return ""
}

// allowedKinds lists the kinds a format may be recorded as. SARIF is emitted by
// linters and by security scanners alike, so the caller picks which it is.
func allowedKinds(f Format) []specv1.EvidenceKind {
	if f == FormatSARIF {
		return []specv1.EvidenceKind{specv1.EvidenceKindStaticAnalysis, specv1.EvidenceKindSecurityScan, specv1.EvidenceKindTypeCheck}
	}
	return []specv1.EvidenceKind{DefaultKind(f)}
}

// Options tunes how a report is interpreted.
type Options struct {
	// Kind overrides DefaultKind where the format allows it (SARIF only).
	Kind specv1.EvidenceKind
	// MinLineCoverage, when set, is the percentage of lines a coverage report
	// must reach to count as a pass. Without it a coverage report is a
	// measurement, recorded as inconclusive, so a pass is never implied
	// without a stated bar.
	MinLineCoverage *float64
}

// Report is the result of parsing one report.
type Report struct {
	Format  Format
	Kind    specv1.EvidenceKind
	Outcome specv1.EvidenceOutcome
	Payload json.RawMessage
}

// Parse reads data as the given format.
func Parse(format Format, data []byte, opts Options) (Report, error) {
	kind := opts.Kind
	if kind == "" {
		kind = DefaultKind(format)
	}
	ok := false
	for _, k := range allowedKinds(format) {
		ok = ok || k == kind
	}
	if !ok {
		return Report{}, fmt.Errorf("%w: a %s report cannot be recorded as %q (allowed: %v)", ErrUnsupported, format, kind, allowedKinds(format))
	}

	var (
		outcome specv1.EvidenceOutcome
		payload any
		err     error
	)
	switch format {
	case FormatGoTest:
		outcome, payload, err = parseGoTest(data)
	case FormatJUnit:
		outcome, payload, err = parseJUnit(data)
	case FormatSARIF:
		outcome, payload, err = parseSARIF(data)
	case FormatCobertura:
		outcome, payload, err = parseCobertura(data, opts)
	case FormatLCOV:
		outcome, payload, err = parseLCOV(data, opts)
	case FormatCycloneDX:
		outcome, payload, err = parseCycloneDX(data)
	default:
		return Report{}, fmt.Errorf("%w: unknown format %q", ErrUnsupported, format)
	}
	if err != nil {
		return Report{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Report{}, fmt.Errorf("evidence: encode payload: %w", err)
	}
	return Report{Format: format, Kind: kind, Outcome: outcome, Payload: encoded}, nil
}

// ReadReport reads at most MaxReportBytes from r.
func ReadReport(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errors.New("evidence: report must not be nil")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("evidence: read report: %w", err)
	}
	if len(data) > MaxReportBytes {
		return nil, fmt.Errorf("evidence: report is larger than %d MiB", MaxReportBytes>>20)
	}
	return data, nil
}

// Detect guesses a report's format from its content.
func Detect(data []byte) (Format, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	switch {
	case len(trimmed) == 0:
		return "", fmt.Errorf("%w: the report is empty", ErrUnsupported)
	case trimmed[0] == '<':
		return detectXML(trimmed)
	case trimmed[0] == '{':
		return detectJSON(trimmed)
	case bytes.HasPrefix(trimmed, []byte("TN:")) || bytes.HasPrefix(trimmed, []byte("SF:")):
		return FormatLCOV, nil
	}
	return "", fmt.Errorf("%w: cannot tell what format this is; pass the format explicitly (%v)", ErrUnsupported, Formats())
}

func detectXML(data []byte) (Format, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("%w: not well-formed XML: %w", ErrUnsupported, err)
		}
		if start, ok := tok.(xml.StartElement); ok {
			switch start.Name.Local {
			case "testsuites", "testsuite":
				return FormatJUnit, nil
			case "coverage":
				return FormatCobertura, nil
			case "bom":
				return "", fmt.Errorf("%w: CycloneDX XML is not supported; use the JSON encoding", ErrUnsupported)
			}
			return "", fmt.Errorf("%w: unrecognised XML root <%s>", ErrUnsupported, start.Name.Local)
		}
	}
}

func detectJSON(data []byte) (Format, error) {
	// go test -json is one JSON object per line; the others are one document.
	firstLine, _, _ := bytes.Cut(data, []byte("\n"))
	var probe map[string]json.RawMessage
	if json.Unmarshal(firstLine, &probe) == nil {
		if _, ok := probe["Action"]; ok {
			return FormatGoTest, nil
		}
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("%w: not a single JSON document: %w", ErrUnsupported, err)
	}
	if raw, ok := probe["bomFormat"]; ok && strings.Contains(string(raw), "CycloneDX") {
		return FormatCycloneDX, nil
	}
	if _, ok := probe["runs"]; ok {
		return FormatSARIF, nil
	}
	return "", fmt.Errorf("%w: unrecognised JSON report", ErrUnsupported)
}

// checkXMLDepth rejects XML nested deeper than maxXMLDepth before it reaches
// the recursive decoder.
func checkXMLDepth(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: not well-formed XML: %w", ErrUnsupported, err)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxXMLDepth {
				return fmt.Errorf("%w: XML is nested more than %d levels deep", ErrUnsupported, maxXMLDepth)
			}
		case xml.EndElement:
			depth--
		}
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// maxFailures caps the failed tests (or similar) a payload lists, keeping
// evidence records small however large the report.
const maxFailures = 50
