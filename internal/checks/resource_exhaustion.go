package checks

// ResourceExhaustionCheck is a supplemental control outside the OWASP MCP
// Top 10:2025 beta taxonomy. It is not registered by the default scanner.
// Rule IDs use the SUP- prefix so they are not reported as MCP10, which is
// context over-sharing.
type ResourceExhaustionCheck struct{}

func (c *ResourceExhaustionCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding
	if !ctx.Server.IsRemote() {
		return findings
	}

	if ctx.Server.RateLimit != nil && !ctx.Server.RateLimit.Enabled {
		findings = append(findings, CheckFinding{
			RuleID:      "SUP-001",
			Name:        "No rate limiting configured",
			Severity:    "medium",
			Description: "MCP server has no rate limiting, making it vulnerable to denial of service through resource exhaustion.",
			Remediation: "Configure rate limiting with appropriate thresholds (requests per second) and payload size limits.",
		})
	}

	if ctx.Server.RateLimit != nil && ctx.Server.RateLimit.Enabled {
		if ctx.Server.RateLimit.MaxPayload <= 0 {
			findings = append(findings, CheckFinding{
				RuleID:      "SUP-002",
				Name:        "No payload size limit",
				Severity:    "medium",
				Description: "Rate limiting is enabled but no maximum payload size is configured, allowing oversized requests.",
				Remediation: "Set a maxPayloadBytes value appropriate for your use case (e.g., 1048576 for 1MB).",
			})
		}
	}

	return findings
}
