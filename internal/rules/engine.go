package rules

import (
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
				continue
			}
			matches := re.FindAllString(configStr, -1)
			if len(matches) > 0 {
				// Redact the actual matched value for secrets
				matchStr := matches[0]
				if strings.Contains(strings.ToLower(rule.OWASPMCP), "mcp04") {
					if len(matchStr) > 20 {
						matchStr = matchStr[:20] + "..."
					}
				}
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
