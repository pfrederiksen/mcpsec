package checks

// PermissionsCheck detects MCP02 — Excessive Tool Permissions / Over-Privileged Tools.
type PermissionsCheck struct{}

var dangerousPermissions = map[string]bool{
	"*":            true,
	"admin":        true,
	"root":         true,
	"sudo":         true,
	"write:*":      true,
	"read:*":       true,
	"execute:*":    true,
	"full_access":  true,
	"all":          true,
	"filesystem:*": true,
	"network:*":    true,
	"shell:*":      true,
	"exec":         true,
	"shell":        true,
	"filesystem":   true,
}

func (c *PermissionsCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding
	if ctx.Server.Command != "" && ctx.Server.SandboxEnabled != nil && !*ctx.Server.SandboxEnabled {
		findings = append(findings, CheckFinding{RuleID: "MCP02-101", Name: "Local server sandbox explicitly disabled", Severity: "high", OWASPMCP: "MCP02", Description: "The client configuration explicitly disables its MCP process sandbox.", Remediation: "Enable the client sandbox and grant only required filesystem and network access.", Match: "sandboxEnabled=false"})
	}

	// Check server-level permissions
	for _, perm := range ctx.Server.Permissions {
		if dangerousPermissions[perm] {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP02-001",
				Name:        "Excessive server permissions",
				Severity:    "critical",
				OWASPMCP:    "MCP02",
				Description: "MCP server is granted overly broad permissions that violate the principle of least privilege.",
				Remediation: "Restrict permissions to only those required by the server's tools. Replace wildcard permissions with specific, scoped grants.",
				Match:       "permission=" + perm,
			})
			break
		}
	}

	// Check tool-level permissions
	for _, tool := range ctx.Server.Tools {
		for _, perm := range tool.Permissions {
			if dangerousPermissions[perm] {
				findings = append(findings, CheckFinding{
					RuleID:      "MCP02-002",
					Name:        "Excessive tool permissions",
					Severity:    "critical",
					OWASPMCP:    "MCP02",
					Description: "Tool is granted overly broad permissions that violate the principle of least privilege.",
					Remediation: "Restrict tool permissions to the minimum required for its function.",
					Match:       "tool=" + tool.Name + " permission=" + perm,
				})
				break
			}
		}
	}

	return findings
}
