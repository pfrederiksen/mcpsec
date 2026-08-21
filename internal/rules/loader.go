package rules

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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
	Scope       string   `yaml:"scope,omitempty" json:"scope,omitempty"`
}

// MatchDef defines what a rule matches against.
type MatchDef struct {
	Path    string `yaml:"path" json:"path"`
	Pattern string `yaml:"pattern" json:"pattern"`
	Type    string `yaml:"type" json:"type"` // regex, jsonpath, semgrep
}

// LoadFile loads a single YAML rule file.
func LoadFile(path string) (*Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading rule file %s: %w", path, err)
	}
	if info.Size() > 1<<20 {
		return nil, fmt.Errorf("rule file %s exceeds 1 MiB limit", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rule file %s: %w", path, err)
	}
	var rule Rule
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rule); err != nil {
		return nil, fmt.Errorf("parsing rule file %s: %w", path, err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parsing rule file %s: multiple YAML documents are not allowed", path)
		}
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
	if validationErrors := ValidateRule(&rule); len(validationErrors) > 0 {
		return nil, fmt.Errorf("rule file %s: %s", path, strings.Join(validationErrors, "; "))
	}
	return &rule, nil
}

// LoadDirectory loads all .yaml and .yml files from a directory.
func LoadDirectory(dir string) ([]*Rule, error) {
	var rules []*Rule
	seenIDs := make(map[string]string)
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
		if previous, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %s in %s and %s", rule.ID, previous, path)
		}
		seenIDs[rule.ID] = path
		rules = append(rules, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
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
		validTypes := map[string]bool{"regex": true, "jsonpath": true, "not_regex": true}
		if !validTypes[rule.Match.Type] {
			errors = append(errors, fmt.Sprintf("invalid match type '%s': must be regex, jsonpath, or not_regex", rule.Match.Type))
		}
	}
	if rule.Match.Pattern == "" {
		errors = append(errors, "missing required field 'match.pattern'")
	} else if _, err := regexp.Compile(rule.Match.Pattern); err != nil {
		errors = append(errors, fmt.Sprintf("invalid match pattern: %v", err))
	}
	if (rule.Match.Type == "jsonpath" || rule.Match.Type == "not_regex") && rule.Match.Path == "" {
		errors = append(errors, "missing required field 'match.path'")
	}
	if rule.Scope != "" && rule.Scope != "any" && rule.Scope != "remote" {
		errors = append(errors, fmt.Sprintf("invalid scope '%s': must be any or remote", rule.Scope))
	}
	return errors
}
