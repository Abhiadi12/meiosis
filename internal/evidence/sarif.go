package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type sarifLog struct {
	Version string `json:"version"`
	Runs    *[]struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID string `json:"ruleId"`
			Level  string `json:"level"`
		} `json:"results"`
	} `json:"runs"`
}

type ruleCount struct {
	Rule  string `json:"rule"`
	Level string `json:"level"`
	Count int    `json:"count"`
}

const maxTopRules = 10

func parseSARIF(data []byte) (specv1.EvidenceOutcome, any, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return "", nil, fmt.Errorf("%w: not a SARIF log: %w", ErrUnsupported, err)
	}
	if log.Runs == nil || !strings.HasPrefix(log.Version, "2.") {
		return "", nil, fmt.Errorf("%w: not a SARIF 2.x log (version %q, runs present: %t)", ErrUnsupported, log.Version, log.Runs != nil)
	}

	counts := map[string]int{"error": 0, "warning": 0, "note": 0}
	rules := map[string]*ruleCount{}
	var tools []string
	seenTool := map[string]bool{}
	total := 0
	for _, run := range *log.Runs {
		if name := run.Tool.Driver.Name; name != "" && !seenTool[name] {
			seenTool[name] = true
			tools = append(tools, name)
		}
		for _, r := range run.Results {
			total++
			// SARIF: a result with no level is a "warning"; level "none" is
			// informational. Anything unrecognised is treated as a warning so
			// it is never silently dropped.
			level := strings.ToLower(r.Level)
			switch level {
			case "error", "warning", "note":
			case "none":
				level = "note"
			default:
				level = "warning"
			}
			counts[level]++
			id := r.RuleID
			if id == "" {
				id = "(no rule id)"
			}
			rc := rules[id+"|"+level]
			if rc == nil {
				rc = &ruleCount{Rule: id, Level: level}
				rules[id+"|"+level] = rc
			}
			rc.Count++
		}
	}

	top := make([]ruleCount, 0, len(rules))
	for _, rc := range rules {
		top = append(top, *rc)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		if top[i].Rule != top[j].Rule {
			return top[i].Rule < top[j].Rule
		}
		return top[i].Level < top[j].Level
	})
	if len(top) > maxTopRules {
		top = top[:maxTopRules]
	}

	outcome := specv1.EvidenceOutcomePass
	switch {
	case counts["error"] > 0:
		outcome = specv1.EvidenceOutcomeFail
	case len(*log.Runs) == 0:
		outcome = specv1.EvidenceOutcomeInconclusive // no tool ran
	}
	if tools == nil {
		tools = []string{}
	}
	payload := map[string]any{"format": "sarif", "tools": tools, "results": total, "counts": counts, "top_rules": top}
	return outcome, payload, nil
}
