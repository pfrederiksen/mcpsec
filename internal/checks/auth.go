package checks

// AuthCheck detects MCP03 — Missing Authentication / Authorization Controls.
type AuthCheck struct{}

func (c *AuthCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	if ctx.Server.Auth == nil {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP03-001",
			Name:        "Missing authentication configuration",
			Severity:    "critical",
			OWASPMCP:    "MCP03",
			Description: "MCP server has no authentication configuration, allowing unauthenticated access to all tools.",
			Remediation: "Configure authentication using OAuth 2.0, API keys, or mTLS. Ensure all MCP server endpoints require valid credentials.",
		})
	} else if ctx.Server.Auth.Type == "" {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP03-002",
			Name:        "Authentication type not specified",
			Severity:    "high",
			OWASPMCP:    "MCP03",
			Description: "Authentication block exists but no type is specified, which may result in auth being silently disabled.",
			Remediation: "Specify an authentication type (e.g., 'oauth2', 'apikey', 'mtls') in the auth configuration.",
		})
	}

	return findings
}
