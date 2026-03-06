package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Rule represents a YAML-defined security rule.
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Severity    string   `yaml:"severity" json:"severity"`
	OWASPMCP    string   `yaml:"owasp_mcp" json:"owasp_mcp"`
	Description string   `yaml:"description" json:"description"`
	References  []string `yaml:"references" json:"references"`
	Match       MatchDef `yaml:"match" json:"match"`
	Remediation string   `yaml:"remediation" json:"remediation"`
}

// MatchDef defines what a rule matches against.
type MatchDef struct {
	Path    string `yaml:"path" json:"path"`
	Pattern string `yaml:"pattern" json:"pattern"`
	Type    string `yaml:"type" json:"type"` // regex, jsonpath, semgrep
}

// LoadFile loads a single YAML rule file.
func LoadFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rule file %s: %w", path, err)
	}
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parsing rule file %s: %w", path, err)
	}
	if rule.ID == "" {
		return nil, fmt.Errorf("rule file %s: missing required field 'id'", path)
	}
	if rule.Name == "" {
		return nil, fmt.Errorf("rule file %s: missing required field 'name'", path)
	}
	if rule.Severity == "" {
		return nil, fmt.Errorf("rule file %s: missing required field 'severity'", path)
	}
	return &rule, nil
}

// LoadDirectory loads all .yaml and .yml files from a directory.
func LoadDirectory(dir string) ([]*Rule, error) {
	var rules []*Rule
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rule, err := LoadFile(path)
		if err != nil {
			return err
		}
		rules = append(rules, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// ValidateRule checks that a rule has all required fields and valid values.
func ValidateRule(rule *Rule) []string {
	var errors []string
	if rule.ID == "" {
		errors = append(errors, "missing required field 'id'")
	}
	if rule.Name == "" {
		errors = append(errors, "missing required field 'name'")
	}
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	if !validSeverities[rule.Severity] {
		errors = append(errors, fmt.Sprintf("invalid severity '%s': must be critical, high, medium, low, or info", rule.Severity))
	}
	if rule.OWASPMCP == "" {
		errors = append(errors, "missing required field 'owasp_mcp'")
	}
	if rule.Match.Type == "" {
		errors = append(errors, "missing required field 'match.type'")
	} else {
		validTypes := map[string]bool{"regex": true, "jsonpath": true, "semgrep": true}
		if !validTypes[rule.Match.Type] {
			errors = append(errors, fmt.Sprintf("invalid match type '%s': must be regex, jsonpath, or semgrep", rule.Match.Type))
		}
	}
	return errors
}
