package checks

// AuditLoggingCheck detects OWASP MCP08 — Lack of Audit and Telemetry.
type AuditLoggingCheck struct{}

func (c *AuditLoggingCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding
	if !ctx.Server.IsRemote() {
		return findings
	}

	if ctx.Server.Logging == nil {
		return findings
	}

	if !ctx.Server.Logging.Enabled {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP08-101",
			Name:        "Logging explicitly disabled",
			Severity:    "high",
			OWASPMCP:    "MCP08",
			Description: "Logging is explicitly disabled, preventing detection and investigation of security incidents.",
			Remediation: "Enable logging and configure appropriate log levels and destinations.",
		})
	}

	if !ctx.Server.Logging.Audit {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP08-102",
			Name:        "Audit logging not enabled",
			Severity:    "medium",
			OWASPMCP:    "MCP08",
			Description: "Audit logging is not enabled, preventing tracking of who invoked which tools and when.",
			Remediation: "Enable audit logging to maintain a record of all tool invocations including caller identity, timestamp, and parameters.",
		})
	}

	return findings
}
