package checks

// ResourceExhaustionCheck detects MCP10 — Denial of Service via Resource Exhaustion.
type ResourceExhaustionCheck struct{}

func (c *ResourceExhaustionCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	if ctx.Server.RateLimit == nil || !ctx.Server.RateLimit.Enabled {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP10-001",
			Name:        "No rate limiting configured",
			Severity:    "medium",
			OWASPMCP:    "MCP10",
			Description: "MCP server has no rate limiting, making it vulnerable to denial of service through resource exhaustion.",
			Remediation: "Configure rate limiting with appropriate thresholds (requests per second) and payload size limits.",
		})
	}

	if ctx.Server.RateLimit != nil && ctx.Server.RateLimit.Enabled {
		if ctx.Server.RateLimit.MaxPayload <= 0 {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP10-002",
				Name:        "No payload size limit",
				Severity:    "medium",
				OWASPMCP:    "MCP10",
				Description: "Rate limiting is enabled but no maximum payload size is configured, allowing oversized requests.",
				Remediation: "Set a maxPayloadBytes value appropriate for your use case (e.g., 1048576 for 1MB).",
			})
		}
	}

	return findings
}
