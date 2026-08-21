package checks

import (
	"regexp"
	"strings"
)

// ContextExposureCheck detects OWASP MCP10 — Context Injection & Over-Sharing.
type ContextExposureCheck struct{}

var contextWideAccess = regexp.MustCompile(`(?i)(--root|--allow-read|--filesystem|--mount)(=|\s+)(~|/|/home(?:/[^/\s]+)?|/users(?:/[^/\s]+)?)(\s|$)|(^|\s)/:/`)

func (c *ContextExposureCheck) Run(ctx CheckContext) []CheckFinding {
	joined := strings.Join(ctx.Server.Args, " ")
	if ctx.Server.CWD == "/" || ctx.Server.CWD == "~" {
		joined += " --root " + ctx.Server.CWD
	}
	if contextWideAccess.MatchString(joined) {
		return []CheckFinding{{
			RuleID: "MCP10-101", Name: "Broad host context exposed to MCP server", Severity: "high", OWASPMCP: "MCP10",
			Description: "The server arguments appear to expose a home, system, or filesystem-root scope, increasing cross-task data exposure.",
			Remediation: "Grant only task-specific directories and use read-only mounts where possible.", Match: "args",
		}}
	}
	return nil
}
