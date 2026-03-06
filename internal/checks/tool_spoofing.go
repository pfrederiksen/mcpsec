package checks

import (
	"fmt"
	"strings"
)

// ToolSpoofingCheck detects MCP06 — Tool Definition Spoofing / Integrity Violations.
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
				RuleID:      "MCP06-001",
				Name:        "Duplicate tool name detected",
				Severity:    "high",
				OWASPMCP:    "MCP06",
				Description: "Multiple tools share the same name, which could allow a malicious tool to shadow a legitimate one.",
				Remediation: "Ensure all tool names are unique within a server. Implement tool name validation during registration.",
				Match:       "tool=" + name,
			})
		}
	}

	// Check for missing integrity hashes — deduplicate into a single finding
	var toolsMissingHash []string
	for _, tool := range ctx.Server.Tools {
		if tool.Hash == "" {
			toolsMissingHash = append(toolsMissingHash, tool.Name)
		}
	}
	if len(toolsMissingHash) > 0 {
		match := fmt.Sprintf("%d tool(s): %s", len(toolsMissingHash), strings.Join(toolsMissingHash, ", "))
		findings = append(findings, CheckFinding{
			RuleID:      "MCP06-002",
			Name:        "Missing tool integrity hash",
			Severity:    "medium",
			OWASPMCP:    "MCP06",
			Description: fmt.Sprintf("%d tool(s) lack integrity hashes, making it impossible to verify they have not been tampered with.", len(toolsMissingHash)),
			Remediation: "Add a cryptographic hash (SHA-256) to each tool definition and verify it before execution.",
			Match:       match,
		})
	}

	return findings
}
