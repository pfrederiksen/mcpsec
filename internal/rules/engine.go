package rules

import (
	"encoding/json"
	"regexp"
	"strings"
)

type RuleFinding struct {
	RuleID, Name, Severity, OWASPMCP, Description, Remediation, Match string
}

type Engine struct{ Rules []*Rule }

func NewEngine() *Engine { return &Engine{} }

func (e *Engine) LoadFromDirectory(dir string) error {
	loaded, err := LoadDirectory(dir)
	if err != nil {
		return err
	}
	e.Rules = append(e.Rules, loaded...)
	return nil
}

// Evaluate runs rules against one server only, preventing matches in one
// server from being attributed to every server in the input document.
func (e *Engine) Evaluate(serverName string, server interface{}) []RuleFinding {
	serverJSON, err := json.Marshal(server)
	if err != nil {
		return nil
	}
	var serverValue interface{}
	if err := json.Unmarshal(serverJSON, &serverValue); err != nil {
		return nil
	}

	var findings []RuleFinding
	for _, rule := range e.Rules {
		if rule.Scope == "remote" && !isRemoteServer(serverValue) {
			continue
		}
		re := regexp.MustCompile(rule.Match.Pattern) // validated when loaded
		values := []interface{}{json.RawMessage(serverJSON)}
		if rule.Match.Type == "jsonpath" || rule.Match.Type == "not_regex" {
			values = jsonPathValues(serverValue, normalizeServerPath(rule.Match.Path, serverName))
		}
		for _, value := range values {
			match := re.FindString(stringify(value))
			matched := match != ""
			if rule.Match.Type == "not_regex" {
				matched = !matched
				match = "path=" + rule.Match.Path
			}
			if !matched {
				continue
			}
			if rule.Match.Type == "jsonpath" {
				match = "path=" + rule.Match.Path + " value=" + match
			}
			findings = append(findings, RuleFinding{
				RuleID: rule.ID, Name: rule.Name, Severity: rule.Severity,
				OWASPMCP: rule.OWASPMCP, Description: rule.Description,
				Remediation: rule.Remediation, Match: redactMatch(match, rule.OWASPMCP),
			})
			break
		}
	}
	return findings
}

func isRemoteServer(value interface{}) bool {
	server, ok := value.(map[string]interface{})
	if !ok {
		return false
	}
	if rawURL, ok := server["url"].(string); ok && rawURL != "" {
		return true
	}
	transport, ok := server["transport"].(string)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "http", "https", "sse", "streamable-http", "websocket", "ws", "wss":
		return true
	default:
		return false
	}
}

func normalizeServerPath(path, serverName string) string {
	p := strings.TrimPrefix(strings.TrimSpace(path), "$")
	p = strings.TrimPrefix(p, ".")
	if p == "mcpServers" || p == "mcpServers[*]" || p == "mcpServers.*" {
		return "$"
	}
	for _, prefix := range []string{"mcpServers.*.", "mcpServers[*].", "mcpServers." + serverName + "."} {
		if strings.HasPrefix(p, prefix) {
			return "$." + strings.TrimPrefix(p, prefix)
		}
	}
	return "$." + p
}

// jsonPathValues implements fields, wildcards, and recursive descent.
func jsonPathValues(root interface{}, path string) []interface{} {
	if path == "$" || path == "$." {
		return []interface{}{root}
	}
	p := strings.TrimPrefix(path, "$")
	p = strings.ReplaceAll(p, "[*]", ".*")
	if strings.Contains(p, "..") {
		parts := strings.SplitN(p, "..", 2)
		basePath := "$"
		if strings.Trim(parts[0], ".") != "" {
			basePath = "$." + strings.Trim(parts[0], ".")
		}
		base := jsonPathValues(root, basePath)
		var out []interface{}
		for _, value := range base {
			collectRecursive(value, strings.TrimPrefix(parts[1], "."), &out)
		}
		return out
	}
	p = strings.TrimPrefix(p, ".")
	values := []interface{}{root}
	for _, token := range strings.Split(p, ".") {
		if token == "" {
			continue
		}
		var next []interface{}
		for _, value := range values {
			switch node := value.(type) {
			case map[string]interface{}:
				if token == "*" {
					for _, child := range node {
						next = append(next, child)
					}
				} else if child, ok := node[token]; ok {
					next = append(next, child)
				}
			case []interface{}:
				if token == "*" {
					next = append(next, node...)
				}
			}
		}
		values = next
	}
	return values
}

func collectRecursive(value interface{}, field string, out *[]interface{}) {
	switch node := value.(type) {
	case map[string]interface{}:
		if child, ok := node[field]; ok {
			*out = append(*out, child)
		}
		for _, child := range node {
			collectRecursive(child, field, out)
		}
	case []interface{}:
		for _, child := range node {
			collectRecursive(child, field, out)
		}
	}
}

func stringify(value interface{}) string {
	if s, ok := value.(string); ok {
		return s
	}
	b, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(b)
}

func redactMatch(match, owaspMCP string) string {
	lower := strings.ToLower(match)
	if strings.Contains(strings.ToLower(owaspMCP), "mcp04") {
		return redactValue(match)
	}
	for _, indicator := range []string{"key=", "token=", "secret=", "password=", "credential="} {
		if strings.Contains(lower, indicator) {
			return redactValue(match)
		}
	}
	return match
}

func redactValue(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:8] + "***"
}
