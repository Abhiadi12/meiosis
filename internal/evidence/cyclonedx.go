package evidence

import (
	"encoding/json"
	"fmt"
	"strings"

	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
)

type cycloneDXBOM struct {
	BOMFormat       string            `json:"bomFormat"`
	SpecVersion     string            `json:"specVersion"`
	Components      []json.RawMessage `json:"components"`
	Vulnerabilities *[]struct {
		Ratings []struct {
			Severity string `json:"severity"`
		} `json:"ratings"`
	} `json:"vulnerabilities"`
}

var severityRank = map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func parseCycloneDX(data []byte) (specv1.EvidenceOutcome, any, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return "", nil, fmt.Errorf("%w: not a CycloneDX BOM: %w", ErrUnsupported, err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return "", nil, fmt.Errorf("%w: not a CycloneDX BOM (bomFormat %q)", ErrUnsupported, bom.BOMFormat)
	}

	payload := map[string]any{"format": "cyclonedx", "spec_version": bom.SpecVersion, "components": len(bom.Components)}

	// An SBOM that carries no vulnerability analysis says what is in the
	// software, not that it is free of known vulnerabilities, so it cannot
	// support a pass.
	if bom.Vulnerabilities == nil {
		return specv1.EvidenceOutcomeInconclusive, payload, nil
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	for _, v := range *bom.Vulnerabilities {
		worst := "unknown"
		for _, r := range v.Ratings {
			sev := strings.ToLower(r.Severity)
			if sev == "info" || sev == "none" {
				sev = "low"
			}
			if rank, ok := severityRank[sev]; ok && rank > severityRank[worst] {
				worst = sev
			}
		}
		counts[worst]++
	}
	payload["vulnerabilities"] = counts
	outcome := specv1.EvidenceOutcomePass
	if counts["critical"]+counts["high"] > 0 {
		outcome = specv1.EvidenceOutcomeFail
	}
	return outcome, payload, nil
}
