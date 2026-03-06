package checks

import (
	"net/url"
	"strings"
)

// TransportCheck detects MCP07 — Insecure Transport.
type TransportCheck struct{}

var weakTLSVersions = map[string]bool{
	"1.0":    true,
	"1.1":    true,
	"tls1.0": true,
	"tls1.1": true,
	"ssl3":   true,
	"ssl3.0": true,
}

func (c *TransportCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	// Check server URL scheme
	if ctx.Server.URL != "" {
		parsed, err := url.Parse(ctx.Server.URL)
		if err == nil && parsed.Scheme == "http" {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP07-001",
				Name:        "Insecure HTTP transport",
				Severity:    "high",
				OWASPMCP:    "MCP07",
				Description: "MCP server communicates over plain HTTP, exposing data in transit to eavesdropping and tampering.",
				Remediation: "Use HTTPS for all MCP server communications. Configure TLS 1.2+ with strong cipher suites.",
				Match:       "url=" + ctx.Server.URL,
			})
		}
	}

	// Check TLS configuration
	if ctx.Server.URL != "" {
		parsed, err := url.Parse(ctx.Server.URL)
		if err == nil && parsed != nil && (parsed.Scheme == "https" || parsed.Scheme == "wss") {
			if ctx.Server.TLS != nil && !ctx.Server.TLS.Enabled {
				findings = append(findings, CheckFinding{
					RuleID:      "MCP07-002",
					Name:        "TLS explicitly disabled",
					Severity:    "critical",
					OWASPMCP:    "MCP07",
					Description: "TLS is explicitly disabled in the configuration despite using an HTTPS/WSS URL.",
					Remediation: "Enable TLS and configure it with TLS 1.2+ and strong cipher suites.",
				})
			}
		}
	}

	// Check for weak TLS versions
	if ctx.Server.TLS != nil && ctx.Server.TLS.MinVer != "" {
		if weakTLSVersions[strings.ToLower(ctx.Server.TLS.MinVer)] {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP07-003",
				Name:        "Weak TLS version configured",
				Severity:    "high",
				OWASPMCP:    "MCP07",
				Description: "TLS minimum version is set to a known-weak version vulnerable to protocol downgrade attacks.",
				Remediation: "Set minimum TLS version to 1.2 or higher.",
				Match:       "tls.minVersion=" + ctx.Server.TLS.MinVer,
			})
		}
	}

	return findings
}
