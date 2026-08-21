package checks

import (
	"net/netip"
	"net/url"
	"strings"
)

// UnsafeResourceCheck detects MCP05 — Unsafe Resource Access (SSRF-equivalent).
type UnsafeResourceCheck struct{}

var dangerousSchemes = map[string]bool{
	"file":   true,
	"gopher": true,
	"dict":   true,
	"ftp":    true,
}

func (c *UnsafeResourceCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	uris := collectURIs(ctx)
	for _, entry := range uris {
		parsed, err := url.Parse(entry.uri)
		if err != nil {
			continue
		}

		if dangerousSchemes[parsed.Scheme] {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP05-001",
				Name:        "Dangerous URI scheme in tool configuration",
				Severity:    "high",
				OWASPMCP:    "MCP05",
				Description: "Tool URI uses a scheme that can be exploited for SSRF or local file access.",
				Remediation: "Restrict tool URIs to https:// only. Implement an allowlist of permitted schemes and hosts.",
				Match:       entry.source + " uri=" + safeURI(parsed),
			})
			continue
		}

		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		if isInternalHost(host) {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP05-002",
				Name:        "Tool URI targets internal network",
				Severity:    "high",
				OWASPMCP:    "MCP05",
				Description: "Tool URI points to an internal or loopback address, which can be exploited for SSRF.",
				Remediation: "Restrict tool URIs to external, validated endpoints. Implement network-level controls to prevent access to internal resources.",
				Match:       entry.source + " uri=" + safeURI(parsed),
			})
		}
	}

	return findings
}

func isInternalHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast()
}

func safeURI(parsed *url.URL) string {
	copy := *parsed
	copy.User = nil
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	return copy.String()
}

type uriEntry struct {
	uri    string
	source string
}

func collectURIs(ctx CheckContext) []uriEntry {
	var entries []uriEntry
	if ctx.Server.URL != "" {
		entries = append(entries, uriEntry{uri: ctx.Server.URL, source: "server"})
	}
	for _, tool := range ctx.Server.Tools {
		if tool.URI != "" {
			entries = append(entries, uriEntry{uri: tool.URI, source: "tool=" + tool.Name})
		}
	}
	return entries
}
