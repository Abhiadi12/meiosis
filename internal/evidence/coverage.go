package evidence

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type coverageTotals struct {
	files                          int
	linesValid, linesCovered       int
	branchesValid, branchesCovered int
}

// payload turns totals into a coverage payload and its outcome. rates are
// fractions in [0,1], as the schema requires.
func (c coverageTotals) payload(format string, opts Options) (specv1.EvidenceOutcome, map[string]any) {
	p := map[string]any{
		"format": format, "files": c.files, "lines_valid": c.linesValid, "lines_covered": c.linesCovered,
		"branches_valid": c.branchesValid, "branches_covered": c.branchesCovered,
	}
	lineRate := 0.0
	if c.linesValid > 0 {
		lineRate = float64(c.linesCovered) / float64(c.linesValid)
	}
	p["line_rate"] = lineRate
	if c.branchesValid > 0 {
		p["branch_rate"] = float64(c.branchesCovered) / float64(c.branchesValid)
	}

	if c.linesValid == 0 {
		return specv1.EvidenceOutcomeInconclusive, p // nothing was measured
	}
	if opts.MinLineCoverage == nil {
		return specv1.EvidenceOutcomeInconclusive, p // a measurement, not a verdict
	}
	p["threshold_percent"] = *opts.MinLineCoverage
	if lineRate*100 >= *opts.MinLineCoverage {
		return specv1.EvidenceOutcomePass, p
	}
	return specv1.EvidenceOutcomeFail, p
}

// consistent rejects totals that cannot describe a real measurement, so a
// malformed report is refused rather than recorded with an impossible rate.
func (c coverageTotals) consistent(format string) error {
	if c.linesCovered > c.linesValid {
		return fmt.Errorf("%w: %s declares more covered lines (%d) than valid lines (%d)", ErrUnsupported, format, c.linesCovered, c.linesValid)
	}
	if c.branchesCovered > c.branchesValid {
		return fmt.Errorf("%w: %s declares more covered branches (%d) than valid branches (%d)", ErrUnsupported, format, c.branchesCovered, c.branchesValid)
	}
	return nil
}

func validThreshold(opts Options) error {
	if opts.MinLineCoverage != nil && (*opts.MinLineCoverage < 0 || *opts.MinLineCoverage > 100) {
		return fmt.Errorf("%w: the coverage threshold must be between 0 and 100", ErrUnsupported)
	}
	return nil
}

type coberturaLine struct {
	Hits   string `xml:"hits,attr"`
	Branch string `xml:"branch,attr"`
	Cond   string `xml:"condition-coverage,attr"`
}

type coberturaRoot struct {
	XMLName       xml.Name
	LinesValid    string `xml:"lines-valid,attr"`
	LinesCovered  string `xml:"lines-covered,attr"`
	BranchesValid string `xml:"branches-valid,attr"`
	BranchesCov   string `xml:"branches-covered,attr"`
	Packages      []struct {
		Classes []struct {
			Filename string          `xml:"filename,attr"`
			Lines    []coberturaLine `xml:"lines>line"`
			Methods  []struct {
				Lines []coberturaLine `xml:"lines>line"`
			} `xml:"methods>method"`
		} `xml:"classes>class"`
	} `xml:"packages>package"`
}

func parseCobertura(data []byte, opts Options) (specv1.EvidenceOutcome, any, error) {
	if err := validThreshold(opts); err != nil {
		return "", nil, err
	}
	if err := checkXMLDepth(data); err != nil {
		return "", nil, err
	}
	var root coberturaRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return "", nil, fmt.Errorf("%w: not a Cobertura report: %w", ErrUnsupported, err)
	}
	if root.XMLName.Local != "coverage" {
		return "", nil, fmt.Errorf("%w: not a Cobertura report: root element is <%s>", ErrUnsupported, root.XMLName.Local)
	}

	// Count the line elements themselves: the attributes on the root are
	// summaries a tool may get wrong, and are only used when no lines are listed.
	var c coverageTotals
	filesSeen := map[string]bool{}
	for _, pkg := range root.Packages {
		for _, class := range pkg.Classes {
			if !filesSeen[class.Filename] {
				filesSeen[class.Filename] = true
				c.files++
			}
			// A class's own <lines> lists every line (methods repeat a subset),
			// so methods are not counted again.
			for _, l := range class.Lines {
				c.linesValid++
				if hits, err := strconv.Atoi(l.Hits); err == nil && hits > 0 {
					c.linesCovered++
				}
				if strings.EqualFold(l.Branch, "true") {
					if covered, total, ok := parseCondition(l.Cond); ok {
						c.branchesValid += total
						c.branchesCovered += covered
					}
				}
			}
		}
	}
	if c.linesValid == 0 {
		c.linesValid = atoiOrZero(root.LinesValid)
		c.linesCovered = atoiOrZero(root.LinesCovered)
		c.branchesValid = atoiOrZero(root.BranchesValid)
		c.branchesCovered = atoiOrZero(root.BranchesCov)
	}
	if err := c.consistent("Cobertura"); err != nil {
		return "", nil, err
	}
	outcome, payload := c.payload("cobertura", opts)
	return outcome, payload, nil
}

// parseCondition reads Cobertura's "75% (3/4)" condition-coverage attribute.
func parseCondition(s string) (covered, total int, ok bool) {
	lparen, rparen := strings.Index(s, "("), strings.Index(s, ")")
	if lparen < 0 || rparen < lparen {
		return 0, 0, false
	}
	a, b, found := strings.Cut(s[lparen+1:rparen], "/")
	if !found {
		return 0, 0, false
	}
	covered, errA := strconv.Atoi(strings.TrimSpace(a))
	total, errB := strconv.Atoi(strings.TrimSpace(b))
	if errA != nil || errB != nil || covered < 0 || total < covered {
		return 0, 0, false
	}
	return covered, total, true
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func parseLCOV(data []byte, opts Options) (specv1.EvidenceOutcome, any, error) {
	if err := validThreshold(opts); err != nil {
		return "", nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var c coverageTotals
	var (
		inRecord                     bool
		daValid, daCovered           int
		lf, lh, brf, brh             int
		sawLF, sawLH, sawBRF, sawBRH bool
	)
	flush := func() {
		if !inRecord {
			return
		}
		valid, covered := daValid, daCovered
		if valid == 0 && sawLF && sawLH {
			valid, covered = lf, lh // no per-line data: trust the file's own totals
		}
		c.linesValid += valid
		c.linesCovered += covered
		if sawBRF && sawBRH {
			c.branchesValid += brf
			c.branchesCovered += brh
		}
		daValid, daCovered, lf, lh, brf, brh = 0, 0, 0, 0, 0, 0
		sawLF, sawLH, sawBRF, sawBRH = false, false, false, false
		inRecord = false
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "SF:"):
			flush()
			inRecord = true
			c.files++
		case strings.HasPrefix(line, "DA:"):
			parts := strings.Split(line[3:], ",")
			if len(parts) < 2 {
				return "", nil, fmt.Errorf("%w: malformed LCOV line %q", ErrUnsupported, truncate(line, 80))
			}
			hits, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			if err != nil {
				return "", nil, fmt.Errorf("%w: malformed LCOV line %q", ErrUnsupported, truncate(line, 80))
			}
			daValid++
			if hits > 0 {
				daCovered++
			}
		case strings.HasPrefix(line, "LF:"):
			lf, sawLF = atoiOrZero(line[3:]), true
		case strings.HasPrefix(line, "LH:"):
			lh, sawLH = atoiOrZero(line[3:]), true
		case strings.HasPrefix(line, "BRF:"):
			brf, sawBRF = atoiOrZero(line[4:]), true
		case strings.HasPrefix(line, "BRH:"):
			brh, sawBRH = atoiOrZero(line[4:]), true
		case line == "end_of_record":
			flush()
		}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("%w: read LCOV: %w", ErrUnsupported, err)
	}
	flush()
	if c.files == 0 {
		return "", nil, fmt.Errorf("%w: not an LCOV report: no SF: records", ErrUnsupported)
	}
	if err := c.consistent("LCOV"); err != nil {
		return "", nil, err
	}
	outcome, payload := c.payload("lcov", opts)
	return outcome, payload, nil
}
