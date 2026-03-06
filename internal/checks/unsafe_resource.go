package checks

import (
	"net/url"
	"strings"
)

// UnsafeResourceCheck detects MCP05 — Unsafe Resource Access (SSRF-equivalent).
type UnsafeResourceCheck struct{}

var internalNetworks = []string{
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"10.",
	"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
	"172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
	"172.28.", "172.29.", "172.30.", "172.31.",
	"192.168.",
	"169.254.",
	"[::1]",
	"metadata.google.internal",
	"169.254.169.254",
}

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
				Match:       entry.source + " uri=" + entry.uri,
			})
			continue
		}

		host := strings.ToLower(parsed.Hostname())
		for _, internal := range internalNetworks {
			if host == internal || strings.HasPrefix(host, internal) {
				findings = append(findings, CheckFinding{
					RuleID:      "MCP05-002",
					Name:        "Tool URI targets internal network",
					Severity:    "high",
					OWASPMCP:    "MCP05",
					Description: "Tool URI points to an internal or loopback address, which can be exploited for SSRF.",
					Remediation: "Restrict tool URIs to external, validated endpoints. Implement network-level controls to prevent access to internal resources.",
					Match:       entry.source + " uri=" + entry.uri,
				})
				break
			}
		}
	}

	return findings
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
