package checks

import (
	"fmt"
	"regexp"
	"strings"
)

// SecretsCheck detects MCP04 — Sensitive Data Exposure.
type SecretsCheck struct{}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|credential|private[_-]?key|auth)\s*[:=]\s*['"]?[A-Za-z0-9+/=_\-]{20,}`),
	regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{20,}`),                 // OpenAI-style keys
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),                 // GitHub PAT
	regexp.MustCompile(`(?i)gho_[a-zA-Z0-9]{36}`),                 // GitHub OAuth
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),                    // AWS access key
	regexp.MustCompile(`(?i)xox[bpoas]-[a-zA-Z0-9\-]{10,}`),      // Slack tokens
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`),     // Bearer tokens
	regexp.MustCompile(`(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY`), // PEM private keys
}

func (c *SecretsCheck) Run(ctx CheckContext) []CheckFinding {
	var findings []CheckFinding

	// Check server-level environment variables
	for key, val := range ctx.Server.Environment {
		if containsSecret(key, val) {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP04-001",
				Name:        "Plain-text secret in server environment",
				Severity:    "critical",
				OWASPMCP:    "MCP04",
				Description: "Server environment variable contains a plain-text secret or API key, exposing credentials to any process reading the config.",
				Remediation: "Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault) and inject at runtime via environment variable references, not literals.",
				Match:       fmt.Sprintf("env=%s", key),
			})
			break
		}
	}

	// Check tool-level environment variables
	for _, tool := range ctx.Server.Tools {
		for key, val := range tool.Environment {
			if containsSecret(key, val) {
				findings = append(findings, CheckFinding{
					RuleID:      "MCP04-002",
					Name:        "Plain-text secret in tool environment",
					Severity:    "critical",
					OWASPMCP:    "MCP04",
					Description: "Tool environment variable contains a plain-text secret or API key.",
					Remediation: "Move secrets to a secrets manager and inject at runtime via environment variable references, not literals.",
					Match:       fmt.Sprintf("tool=%s env=%s", tool.Name, key),
				})
			}
		}
	}

	// Check auth config for inline credentials
	if ctx.Server.Auth != nil {
		if ctx.Server.Auth.Token != "" {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP04-003",
				Name:        "Inline auth token in configuration",
				Severity:    "critical",
				OWASPMCP:    "MCP04",
				Description: "Authentication token is stored inline in the configuration file.",
				Remediation: "Reference the token via an environment variable (e.g., ${AUTH_TOKEN}) rather than embedding it in the config.",
				Match:       "auth.token",
			})
		}
		if ctx.Server.Auth.APIKey != "" {
			findings = append(findings, CheckFinding{
				RuleID:      "MCP04-004",
				Name:        "Inline API key in configuration",
				Severity:    "critical",
				OWASPMCP:    "MCP04",
				Description: "API key is stored inline in the configuration file.",
				Remediation: "Reference the API key via an environment variable rather than embedding it in the config.",
				Match:       "auth.apiKey",
			})
		}
	}

	return findings
}

func containsSecret(key, val string) bool {
	keyLower := strings.ToLower(key)
	sensitiveKeywords := []string{"key", "secret", "token", "password", "credential", "private", "auth"}
	hasSensitiveKey := false
	for _, kw := range sensitiveKeywords {
		if strings.Contains(keyLower, kw) {
			hasSensitiveKey = true
			break
		}
	}

	if hasSensitiveKey && len(val) >= 8 && !strings.HasPrefix(val, "${") && !strings.HasPrefix(val, "$") {
		return true
	}

	for _, pat := range secretPatterns {
		if pat.MatchString(val) {
			return true
		}
	}

	return false
}
