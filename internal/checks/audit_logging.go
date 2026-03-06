package checks

// AuditLoggingCheck detects MCP09 — Logging and Audit Trail Deficiencies.
type AuditLoggingCheck struct{}

func (c *AuditLoggingCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	if ctx.Server.Logging == nil {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP09-001",
			Name:        "No logging configuration",
			Severity:    "medium",
			OWASPMCP:    "MCP09",
			Description: "MCP server has no logging configuration, making it impossible to detect and investigate security incidents.",
			Remediation: "Enable logging with at least 'info' level and enable audit logging for all tool invocations.",
		})
		return findings
	}

	if !ctx.Server.Logging.Enabled {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP09-002",
			Name:        "Logging explicitly disabled",
			Severity:    "high",
			OWASPMCP:    "MCP09",
			Description: "Logging is explicitly disabled, preventing detection and investigation of security incidents.",
			Remediation: "Enable logging and configure appropriate log levels and destinations.",
		})
	}

	if !ctx.Server.Logging.Audit {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP09-003",
			Name:        "Audit logging not enabled",
			Severity:    "medium",
			OWASPMCP:    "MCP09",
			Description: "Audit logging is not enabled, preventing tracking of who invoked which tools and when.",
			Remediation: "Enable audit logging to maintain a record of all tool invocations including caller identity, timestamp, and parameters.",
		})
	}

	return findings
}
