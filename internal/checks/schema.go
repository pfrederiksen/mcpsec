package checks

import (
	"fmt"
	"strings"
)

// SchemaCheck detects MCP08 — Unvalidated Tool Input Schemas.
type SchemaCheck struct{}

func (c *SchemaCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	// Deduplicate per-tool findings into a single finding with count
	var toolsMissingSchema []string
	for _, tool := range ctx.Server.Tools {
		if len(tool.InputSchema) == 0 {
			toolsMissingSchema = append(toolsMissingSchema, tool.Name)
		}
	}
	if len(toolsMissingSchema) > 0 {
		match := fmt.Sprintf("%d tool(s): %s", len(toolsMissingSchema), strings.Join(toolsMissingSchema, ", "))
		findings = append(findings, CheckFinding{
			RuleID:      "MCP08-001",
			Name:        "Missing input schema for tool",
			Severity:    "medium",
			OWASPMCP:    "MCP08",
			Description: fmt.Sprintf("%d tool(s) lack input schema definitions, meaning inputs cannot be validated before processing.", len(toolsMissingSchema)),
			Remediation: "Define a JSON Schema for tool inputs specifying types, required fields, and constraints.",
			Match:       match,
		})
	}

	// Check server-level schema validation config
	if ctx.Server.Schema == nil || !ctx.Server.Schema.ValidateInput {
		if len(ctx.Server.Tools) > 0 {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP08-002",
				Name:        "Input schema validation not enabled",
				Severity:    "medium",
				OWASPMCP:    "MCP08",
				Description: "Schema validation is not enabled at the server level, allowing malformed or malicious inputs to reach tools.",
				Remediation: "Enable input schema validation in the server configuration to automatically reject invalid tool inputs.",
			})
		}
	}

	return findings
}
