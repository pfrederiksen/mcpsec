package checks

import (
	"regexp"
	"strings"
)

// StartupCommandCheck detects OWASP MCP05 — Command Injection & Execution risks
// in local server launch configuration. It is deliberately lexical: the scanner
// never executes the configured command.
type StartupCommandCheck struct{}

var (
	shellCommands      = map[string]bool{"sh": true, "bash": true, "zsh": true, "cmd": true, "powershell": true, "pwsh": true}
	destructiveCommand = regexp.MustCompile(`(?i)(^|[;&|]\s*)(sudo\b|rm\s+-[^\n]*r[^\n]*f|del\s+/[sq]|format\s+[a-z]:|mkfs\b|dd\s+if=)`)
	downloadExecute    = regexp.MustCompile(`(?i)(curl|wget|invoke-webrequest)[^\n]*(\||;|&&)[^\n]*(sh|bash|zsh|powershell|pwsh|python|node)\b`)
	sensitivePath      = regexp.MustCompile(`(?i)(\.ssh[/\\]|\.aws[/\\]|\.config[/\\]gcloud|/etc/(shadow|sudoers)|keychain|credentials)`)
	encodedExecution   = regexp.MustCompile(`(?i)(base64\s+(-d|--decode)|frombase64string|certutil\s+-decode)`)
)

func (c *StartupCommandCheck) Run(ctx CheckContext) []CheckFinding {
	command := strings.TrimSpace(ctx.Server.Command)
	if command == "" || ctx.Server.IsRemote() {
		return nil
	}
	joined := strings.Join(append([]string{command}, ctx.Server.Args...), " ")
	base := strings.ToLower(command)
	if slash := strings.LastIndexAny(base, `/\\`); slash >= 0 {
		base = base[slash+1:]
	}
	var findings []CheckFinding
	if shellCommands[base] {
		findings = append(findings, commandFinding("MCP05-101", "Local MCP server launched through a shell", "high",
			"Shell launchers expand metacharacters and turn a configuration change into arbitrary command execution.",
			"Launch the server executable directly with an argument array; avoid shell -c wrappers.", "command="+command))
	}
	patterns := []struct {
		re                                           *regexp.Regexp
		id, name, severity, description, remediation string
	}{
		{destructiveCommand, "MCP05-102", "Destructive or privileged startup command", "critical", "The startup command contains a destructive or privilege-elevating operation.", "Remove privileged/destructive operations and run the MCP server with least privilege."},
		{downloadExecute, "MCP05-103", "Download-and-execute startup chain", "critical", "The startup command downloads content and immediately executes it.", "Install a pinned, verified artifact separately and launch that artifact directly."},
		{encodedExecution, "MCP05-104", "Encoded startup payload", "high", "The startup command decodes content at runtime, which can conceal executable behavior.", "Use a transparent, reviewed, version-controlled server entry point."},
		{sensitivePath, "MCP05-105", "Startup command references sensitive credentials", "high", "The configured process arguments reference a sensitive credential location.", "Remove access to credential directories and grant only the specific files the server requires."},
	}
	for _, p := range patterns {
		if p.re.MatchString(joined) {
			findings = append(findings, commandFinding(p.id, p.name, p.severity, p.description, p.remediation, "command/args"))
		}
	}
	return findings
}

func commandFinding(id, name, severity, description, remediation, match string) CheckFinding {
	return CheckFinding{RuleID: id, Name: name, Severity: severity, OWASPMCP: "MCP05", Description: description, Remediation: remediation, Match: match}
}
