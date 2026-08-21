package checks

import (
	"net/url"
	"strings"
)

// AuthCheck detects OWASP MCP07 — Insufficient Authentication & Authorization.
type AuthCheck struct{}

func (c *AuthCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding
	if !ctx.Server.IsRemote() {
		return findings
	}

	// Standard client config does not describe server-side auth. Only report an
	// explicitly present but incomplete block; active scanning verifies access.
	if ctx.Server.Auth != nil && ctx.Server.Auth.Type == "" {
		findings = append(findings, CheckFinding{
			RuleID:      "MCP07-101",
			Name:        "Authentication type not specified",
			Severity:    "high",
			OWASPMCP:    "MCP07",
			Description: "Authentication block exists but no type is specified, which may result in auth being silently disabled.",
			Remediation: "Specify an authentication type (e.g., 'oauth2', 'apikey', 'mtls') in the auth configuration.",
		})
	}
	if ctx.Server.Auth == nil || !strings.Contains(strings.ToLower(ctx.Server.Auth.Type), "oauth") {
		return findings
	}
	if ctx.Server.Auth.TokenPassthrough {
		findings = append(findings, CheckFinding{RuleID: "MCP07-102", Name: "OAuth access-token passthrough enabled", Severity: "critical", OWASPMCP: "MCP07", Description: "Passing an inbound MCP token to an upstream API violates audience binding and enables confused-deputy attacks.", Remediation: "Exchange for a separate upstream token issued for that API; never forward the MCP access token.", Match: "auth.tokenPassthrough=true"})
	}
	if ctx.Server.Auth.Audience == "" && ctx.Server.Auth.Resource == "" {
		findings = append(findings, CheckFinding{RuleID: "MCP07-103", Name: "OAuth resource or audience binding not declared", Severity: "high", OWASPMCP: "MCP07", Description: "The enriched OAuth configuration declares neither a resource indicator nor an expected token audience.", Remediation: "Use RFC 8707 resource indicators and validate that access tokens are intended for this MCP server."})
	}
	if ctx.Server.Auth.PKCE != nil && !*ctx.Server.Auth.PKCE {
		findings = append(findings, CheckFinding{RuleID: "MCP07-104", Name: "OAuth PKCE explicitly disabled", Severity: "high", OWASPMCP: "MCP07", Description: "The authorization-code flow explicitly disables PKCE.", Remediation: "Require PKCE with the S256 challenge method."})
	}
	if ctx.Server.Auth.RedirectURI != "" {
		redirect, err := url.Parse(ctx.Server.Auth.RedirectURI)
		if err != nil || (redirect.Scheme != "https" && redirect.Hostname() != "localhost" && redirect.Hostname() != "127.0.0.1" && redirect.Hostname() != "::1") {
			findings = append(findings, CheckFinding{RuleID: "MCP07-105", Name: "Unsafe OAuth redirect URI", Severity: "high", OWASPMCP: "MCP07", Description: "The redirect URI is invalid or uses plaintext transport outside loopback development.", Remediation: "Register and exactly validate an HTTPS redirect URI, allowing HTTP only for loopback native-client redirects.", Match: "auth.redirectUri"})
		}
	}

	return findings
}
