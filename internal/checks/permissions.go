package checks

// PermissionsCheck detects MCP02 — Excessive Tool Permissions / Over-Privileged Tools.
type PermissionsCheck struct{}

var dangerousPermissions = map[string]bool{
	"*":               true,
	"admin":           true,
	"root":            true,
	"sudo":            true,
	"write:*":         true,
	"read:*":          true,
	"execute:*":       true,
	"full_access":     true,
	"all":             true,
	"filesystem:*":    true,
	"network:*":       true,
	"shell:*":         true,
	"exec":            true,
	"shell":           true,
	"filesystem":      true,
}

func (c *PermissionsCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

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

	// Flag if no permissions defined at all (implicit full access)
	if len(ctx.Server.Permissions) == 0 {
		hasToolPerms := false
		for _, t := range ctx.Server.Tools {
			if len(t.Permissions) > 0 {
				hasToolPerms = true
				break
			}
		}
		if !hasToolPerms && len(ctx.Server.Tools) > 0 {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP02-003",
				Name:        "No permission boundaries defined",
				Severity:    "high",
				OWASPMCP:    "MCP02",
				Description: "Neither server-level nor tool-level permissions are defined, implying unrestricted access.",
				Remediation: "Define explicit permission boundaries at the server and/or tool level following the principle of least privilege.",
			})
		}
	}

	return findings
}
