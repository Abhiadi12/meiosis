package evidence

import (
	"encoding/xml"
	"fmt"
	"strconv"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type junitProblem struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure"`
	Error     *junitProblem `xml:"error"`
	Skipped   *struct{}     `xml:"skipped"`
}

type junitSuite struct {
	Name   string       `xml:"name,attr"`
	Time   string       `xml:"time,attr"`
	Cases  []junitCase  `xml:"testcase"`
	Nested []junitSuite `xml:"testsuite"`
}

type junitRoot struct {
	XMLName xml.Name
	Name    string       `xml:"name,attr"`
	Time    string       `xml:"time,attr"`
	Cases   []junitCase  `xml:"testcase"`
	Suites  []junitSuite `xml:"testsuite"`
}

type failedTest struct {
	Suite   string `json:"suite,omitempty"`
	Name    string `json:"name"`
	Message string `json:"message,omitempty"`
}

type suiteSummary struct {
	Name     string `json:"name"`
	Tests    int    `json:"tests"`
	Failures int    `json:"failures"`
	Errors   int    `json:"errors"`
	Skipped  int    `json:"skipped"`
}

// maxSuites caps the per-suite breakdown in a payload.
const maxSuites = 100

type junitTotals struct {
	tests, failures, errors, skipped int
	seconds                          float64
	failed                           []failedTest
	suites                           []suiteSummary
}

// tally counts test cases rather than trusting the totals a report declares in
// its attributes, which tools routinely get wrong or omit.
func (t *junitTotals) tally(s junitSuite) {
	sum := suiteSummary{Name: s.Name}
	for _, c := range s.Cases {
		sum.Tests++
		t.tests++
		if secs, err := strconv.ParseFloat(c.Time, 64); err == nil && secs > 0 {
			t.seconds += secs
		}
		suite := c.Classname
		if suite == "" {
			suite = s.Name
		}
		switch {
		case c.Failure != nil:
			sum.Failures++
			t.failures++
			t.fail(suite, c.Name, c.Failure)
		case c.Error != nil:
			sum.Errors++
			t.errors++
			t.fail(suite, c.Name, c.Error)
		case c.Skipped != nil:
			sum.Skipped++
			t.skipped++
		}
	}
	if len(sum.Name) > 0 || sum.Tests > 0 {
		if len(t.suites) < maxSuites {
			t.suites = append(t.suites, sum)
		}
	}
	for _, n := range s.Nested {
		t.tally(n)
	}
}

func (t *junitTotals) fail(suite, name string, p *junitProblem) {
	if len(t.failed) >= maxFailures {
		return
	}
	msg := p.Message
	if msg == "" {
		msg = p.Text
	}
	t.failed = append(t.failed, failedTest{Suite: suite, Name: name, Message: truncate(msg, 500)})
}

func parseJUnit(data []byte) (specv1.EvidenceOutcome, any, error) {
	if err := checkXMLDepth(data); err != nil {
		return "", nil, err
	}
	var root junitRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return "", nil, fmt.Errorf("%w: not a JUnit report: %w", ErrUnsupported, err)
	}
	if root.XMLName.Local != "testsuites" && root.XMLName.Local != "testsuite" {
		return "", nil, fmt.Errorf("%w: not a JUnit report: root element is <%s>", ErrUnsupported, root.XMLName.Local)
	}

	var t junitTotals
	if root.XMLName.Local == "testsuite" {
		t.tally(junitSuite{Name: root.Name, Time: root.Time, Cases: root.Cases, Nested: root.Suites})
	} else {
		for _, s := range root.Suites {
			t.tally(s)
		}
	}

	outcome := specv1.EvidenceOutcomePass
	switch {
	case t.failures+t.errors > 0:
		outcome = specv1.EvidenceOutcomeFail
	case t.tests-t.skipped == 0:
		// Nothing actually ran, so there is nothing to vouch for.
		outcome = specv1.EvidenceOutcomeInconclusive
	}
	payload := map[string]any{
		"format": "junit", "tests": t.tests, "failures": t.failures, "errors": t.errors, "skipped": t.skipped,
		"duration_seconds": t.seconds, "suites": nonNil(t.suites), "failed_tests": nonNilFailed(t.failed),
	}
	return outcome, payload, nil
}

func nonNil(s []suiteSummary) []suiteSummary {
	if s == nil {
		return []suiteSummary{}
	}
	return s
}

func nonNilFailed(s []failedTest) []failedTest {
	if s == nil {
		return []failedTest{}
	}
	return s
}
