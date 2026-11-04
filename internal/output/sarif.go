package output

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
)

// WriteSARIF writes a SARIF 2.1.0 report so GitHub code scanning can place
// findings on a config file or source line.
func WriteSARIF(w io.Writer, findings []FindingInput, version string) error {
	rules := make([]map[string]any, 0)
	ruleIndex := map[string]int{}
	results := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		index, ok := ruleIndex[finding.RuleID]
		if !ok {
			index = len(rules)
			ruleIndex[finding.RuleID] = index
			rule := map[string]any{
				"id":                   finding.RuleID,
				"shortDescription":     map[string]string{"text": finding.Name},
				"fullDescription":      map[string]string{"text": finding.Description},
				"help":                 map[string]string{"text": finding.Remediation},
				"defaultConfiguration": map[string]string{"level": sarifLevel(finding.Severity)},
			}
			if finding.OWASPMCP != "" {
				rule["properties"] = map[string]string{"owasp_mcp": finding.OWASPMCP}
			}
			rules = append(rules, rule)
		}
		line := finding.Line
		if line < 1 {
			line = 1
		}
		uri := filepath.ToSlash(finding.Location)
		if uri == "" {
			uri = finding.Resource
		}
		result := map[string]any{
			"ruleId":    finding.RuleID,
			"ruleIndex": index,
			"level":     sarifLevel(finding.Severity),
			"message":   map[string]string{"text": finding.Name + ": " + finding.Description},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": uri},
					"region":           map[string]int{"startLine": line},
				},
			}},
		}
		if finding.OWASPMCP != "" {
			result["properties"] = map[string]string{"owasp_mcp": finding.OWASPMCP}
		}
		results = append(results, result)
	}
	report := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":    "MCPSec Audit",
					"version": version,
					"rules":   rules,
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
