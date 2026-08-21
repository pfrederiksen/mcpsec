package checks

import "strings"

// IntentFlowCheck detects OWASP MCP06 — Intent Flow Subversion.
type IntentFlowCheck struct{}

var intentSubversionPatterns = []string{
	"without confirmation", "without asking", "do not ask", "silently",
	"automatically approve", "bypass approval", "ignore user intent",
	"always call", "must call this tool", "invoke another tool",
}

func (c *IntentFlowCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding
	for _, tool := range ctx.Server.Tools {
		description := strings.ToLower(tool.Description)
		for _, pattern := range intentSubversionPatterns {
			if strings.Contains(description, pattern) {
				findings = append(findings, CheckFinding{
					RuleID: "MCP06-101", Name: "Tool attempts to subvert user intent or approval", Severity: "high", OWASPMCP: "MCP06",
					Description: "The tool description contains language that suppresses confirmation or forces orchestration behavior.",
					Remediation: "Remove behavioral instructions from tool metadata and require explicit approval for consequential actions.",
					Match:       "tool=" + tool.Name + " pattern=" + pattern,
				})
				break
			}
		}
	}
	return findings
}
