package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// RuleFinding is a finding produced by the YAML rule engine.
type RuleFinding struct {
	RuleID      string
	Name        string
	Severity    string
	OWASPMCP    string
	Description string
	Remediation string
	Match       string
}

// Engine evaluates YAML rules against MCP server configurations.
type Engine struct {
	Rules []*Rule
}

// NewEngine creates a new rule engine.
func NewEngine() *Engine {
	return &Engine{}
}

// LoadFromDirectory loads all rules from a directory.
func (e *Engine) LoadFromDirectory(dir string) error {
	rules, err := LoadDirectory(dir)
	if err != nil {
		return err
	}
	e.Rules = append(e.Rules, rules...)
	return nil
}

// Evaluate runs all loaded rules against a server config and returns findings.
func (e *Engine) Evaluate(serverName string, server interface{}, rawConfig []byte) []RuleFinding {
	var findings []RuleFinding

	configStr := string(rawConfig)

	for _, rule := range e.Rules {
		switch rule.Match.Type {
		case "regex":
			if rule.Match.Pattern == "" {
				continue
			}
			re, err := regexp.Compile(rule.Match.Pattern)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Warning: rule %s: invalid regex %q: %v\n", rule.ID, rule.Match.Pattern, err)
				continue
			}
			matches := re.FindAllString(configStr, 100)
			if len(matches) > 0 {
				matchStr := redactMatch(matches[0], rule.OWASPMCP)
				findings = append(findings, RuleFinding{
					RuleID:      rule.ID,
					Name:        rule.Name,
					Severity:    rule.Severity,
					OWASPMCP:    rule.OWASPMCP,
					Description: rule.Description,
					Remediation: rule.Remediation,
					Match:       matchStr,
				})
			}
		case "jsonpath":
			// JSONPath matching: check if the path pattern appears in the config
			if rule.Match.Path != "" && rule.Match.Pattern != "" {
				re, err := regexp.Compile(rule.Match.Pattern)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "Warning: rule %s: invalid regex %q: %v\n", rule.ID, rule.Match.Pattern, err)
					continue
				}
				if re.MatchString(configStr) {
					findings = append(findings, RuleFinding{
						RuleID:      rule.ID,
						Name:        rule.Name,
						Severity:    rule.Severity,
						OWASPMCP:    rule.OWASPMCP,
						Description: rule.Description,
						Remediation: rule.Remediation,
						Match:       "path=" + rule.Match.Path,
					})
				}
			}
		}
	}

	return findings
}

// redactMatch masks matched values that may contain secrets.
func redactMatch(match, owaspMCP string) string {
	// Always redact for secret-related rules
	if strings.Contains(strings.ToLower(owaspMCP), "mcp04") {
		return redactValue(match)
	}

	// Also redact if the match looks like it contains a secret
	lower := strings.ToLower(match)
	secretIndicators := []string{"key=", "token=", "secret=", "password=", "credential="}
	for _, indicator := range secretIndicators {
		if strings.Contains(lower, indicator) {
			return redactValue(match)
		}
	}

	return match
}

// redactValue masks all but the first few characters of a value.
func redactValue(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:8] + "***"
}
