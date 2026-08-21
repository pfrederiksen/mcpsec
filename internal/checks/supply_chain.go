package checks

import (
	"path/filepath"
	"regexp"
	"strings"
)

// SupplyChainCheck detects OWASP MCP04 — Software Supply Chain Attacks & Dependency Tampering.
type SupplyChainCheck struct{}

var (
	mutablePackage = regexp.MustCompile(`(?i)(^|\s)(npx|npm\s+exec|uvx|pipx\s+run)\s+(?:-{1,2}[^\s]+\s+)*(@?[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?)(?:\s|$)`)
	remoteGitRef   = regexp.MustCompile(`(?i)(git\+https?://|github:|https?://github\.com/)[^\s#]+(?:\s|$)`)
)

func (c *SupplyChainCheck) Run(ctx CheckContext) []CheckFinding {
	if ctx.Server.Command == "" || ctx.Server.IsRemote() {
		return nil
	}
	joined := strings.Join(append([]string{ctx.Server.Command}, ctx.Server.Args...), " ")
	var findings []CheckFinding
	if mutablePackage.MatchString(joined) && !containsPinnedPackage(ctx.Server.Args) {
		findings = append(findings, supplyFinding("MCP04-101", "Unpinned package executed as MCP server", "high", "A package runner executes a mutable package reference; a future publish can replace the code that runs locally.", "Pin an exact package version and commit the resolved lockfile."))
	}
	baseCommand := strings.ToLower(strings.TrimSuffix(filepath.Base(ctx.Server.Command), filepath.Ext(ctx.Server.Command)))
	if (baseCommand == "docker" || baseCommand == "podman") && !strings.Contains(joined, "@sha256:") {
		findings = append(findings, supplyFinding("MCP04-102", "Mutable container image reference", "high", "The MCP server uses an unpinned or latest container image.", "Pin the image by immutable sha256 digest."))
	}
	if remoteGitRef.MatchString(joined) && !strings.Contains(joined, "#") {
		findings = append(findings, supplyFinding("MCP04-103", "Unpinned source repository reference", "high", "The server is installed or run from a mutable repository branch.", "Pin a reviewed full commit hash and verify the downloaded artifact."))
	}
	return findings
}

func containsPinnedPackage(args []string) bool {
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if strings.HasPrefix(arg, "@") {
			// Scoped npm package: @scope/name@1.2.3.
			if strings.Count(arg, "@") >= 2 && regexp.MustCompile(`@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(arg) {
				return true
			}
		} else if regexp.MustCompile(`(@|==)[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(arg) {
			return true
		}
	}
	return false
}

func supplyFinding(id, name, severity, description, remediation string) CheckFinding {
	return CheckFinding{RuleID: id, Name: name, Severity: severity, OWASPMCP: "MCP04", Description: description, Remediation: remediation, Match: "command/args"}
}
