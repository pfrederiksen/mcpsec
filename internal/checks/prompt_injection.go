package checks

import "strings"

// PromptInjectionCheck detects MCP01 — Prompt Injection via Tool Output.
// Flags tools whose descriptions contain instruction-like patterns that could
// manipulate an LLM consuming tool output.
type PromptInjectionCheck struct{}

var promptInjectionPatterns = []string{
	"ignore previous",
	"ignore all previous",
	"disregard",
	"you are now",
	"act as",
	"system prompt",
	"<|im_start|>",
	"[INST]",
	"override",
	"forget your instructions",
}

func (c *PromptInjectionCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding
	for _, tool := range ctx.Server.Tools {
		desc := strings.ToLower(tool.Description)
		for _, pattern := range promptInjectionPatterns {
			if strings.Contains(desc, pattern) {
				findings = append(findings, CheckFinding{
					RuleID:      "MCP01-001",
					Name:        "Potential prompt injection in tool description",
					Severity:    "high",
					OWASPMCP:    "MCP01",
					Description: "Tool description contains instruction-like language that could be used to manipulate an LLM consuming tool output.",
					Remediation: "Sanitize tool descriptions to remove instruction-like language. Use structured output formats rather than free-text descriptions that could be interpreted as instructions.",
					Match:       "tool=" + tool.Name + " pattern=" + pattern,
				})
				break
			}
		}
	}
	return findings
}
