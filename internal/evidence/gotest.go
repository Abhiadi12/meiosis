package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type testEvent struct {
	Time    time.Time `json:"Time,omitempty"`
	Action  string    `json:"Action"`
	Package string    `json:"Package,omitempty"`
	Test    string    `json:"Test,omitempty"`
	Output  string    `json:"Output,omitempty"`
	Elapsed float64   `json:"Elapsed,omitempty"`
}

func validAction(action string) bool {
	switch action {
	case "start", "run", "pause", "cont", "pass", "fail", "skip", "output", "bench", "build-output", "build-fail":
		return true
	default:
		return false
	}
}

func parseGoTestEvents(data []byte) ([]testEvent, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var events []testEvent
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 {
			continue
		}
		var event testEvent
		if err := json.Unmarshal([]byte(text), &event); err != nil {
			return nil, fmt.Errorf("%w: parse go test JSON line %d: %w", ErrUnsupported, line, err)
		}
		if event.Action == "" {
			return nil, fmt.Errorf("%w: parse go test JSON line %d: missing Action", ErrUnsupported, line)
		}
		if !validAction(event.Action) {
			return nil, fmt.Errorf("%w: parse go test JSON line %d: unsupported Action %q", ErrUnsupported, line, event.Action)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: read go test JSON: %w", ErrUnsupported, err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("%w: parse go test JSON: no events found", ErrUnsupported)
	}
	return events, nil
}

func parseGoTest(data []byte) (specv1.EvidenceOutcome, any, error) {
	events, err := parseGoTestEvents(data)
	if err != nil {
		return "", nil, err
	}

	type key struct{ pkg, test string }
	results := map[key]string{} // test-level terminal action
	output := map[key][]string{}
	var (
		anyFail, anyPass bool
		seconds          float64
		first            time.Time
	)
	for _, e := range events {
		if first.IsZero() && !e.Time.IsZero() {
			first = e.Time
		}
		k := key{e.Package, e.Test}
		switch e.Action {
		case "output", "build-output":
			if e.Test != "" && len(output[k]) < 20 {
				output[k] = append(output[k], e.Output)
			}
		case "pass", "fail", "skip":
			if e.Test != "" {
				results[k] = e.Action
			} else {
				seconds += e.Elapsed // package-level elapsed
			}
			anyFail = anyFail || e.Action == "fail"
			anyPass = anyPass || e.Action == "pass"
		case "build-fail":
			anyFail = true
		}
	}

	tests, failures, skipped := 0, 0, 0
	var failed []failedTest
	keys := make([]key, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pkg != keys[j].pkg {
			return keys[i].pkg < keys[j].pkg
		}
		return keys[i].test < keys[j].test
	})
	for _, k := range keys {
		tests++
		switch results[k] {
		case "fail":
			failures++
			if len(failed) < maxFailures {
				failed = append(failed, failedTest{Suite: k.pkg, Name: k.test, Message: truncate(strings.Join(output[k], ""), 500)})
			}
		case "skip":
			skipped++
		}
	}

	outcome := specv1.EvidenceOutcomeInconclusive
	switch {
	case anyFail:
		outcome = specv1.EvidenceOutcomeFail
	case anyPass:
		outcome = specv1.EvidenceOutcomePass
	}
	payload := map[string]any{
		"format": "go test -json", "tests": tests, "failures": failures, "skipped": skipped,
		"duration_seconds": seconds, "failed_tests": nonNilFailed(failed),
	}
	if !first.IsZero() {
		payload["reported_start"] = first.UTC().Format(time.RFC3339)
	}
	return outcome, payload, nil
}
