package checks

import "strings"

// ToolSpoofingCheck detects OWASP MCP03 — Tool Poisoning.
type ToolSpoofingCheck struct{}

func (c *ToolSpoofingCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	toolNames := make(map[string]int)
	for _, tool := range ctx.Server.Tools {
		toolNames[strings.ToLower(tool.Name)]++
	}

	// Check for duplicate tool names (potential spoofing)
	for name, count := range toolNames {
		if count > 1 {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP03-201",
				Name:        "Duplicate tool name detected",
				Severity:    "high",
				OWASPMCP:    "MCP03",
				Description: "Multiple tools share the same name, which could allow a malicious tool to shadow a legitimate one.",
				Remediation: "Ensure all tool names are unique within a server. Implement tool name validation during registration.",
				Match:       "tool=" + name,
			})
		}
	}

	return findings
}
