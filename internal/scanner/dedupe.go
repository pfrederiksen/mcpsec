package scanner

import "strings"

func (s *Scanner) unapproved(path string, names []string) []Finding {
	found := ShadowFindings([]DiscoveredConfig{{Path: path, Servers: names}}, s.Approved)
	kept := make([]Finding, 0, len(found))
	for _, finding := range found {
		if s.keep(finding) {
			kept = append(kept, finding)
		}
	}
	return kept
}

func serverNames(config *MCPServerConfig) []string {
	names := make([]string, 0, len(config.MCPServers))
	for name := range config.MCPServers {
		names = append(names, name)
	}
	return names
}

func stampLocation(findings []Finding, path string) {
	for i := range findings {
		if findings[i].Location == "" {
			findings[i].Location = path
		}
		if findings[i].Line == 0 {
			findings[i].Line = 1
		}
	}
}

// dedupeFindings drops a YAML rule when a built-in check already covers the
// same category, resource, and field. Distinct built-in findings are kept.
func dedupeFindings(in []Finding) []Finding {
	covered := make(map[string]bool)
	for _, finding := range in {
		if strings.Contains(finding.RuleID, "-R") {
			continue
		}
		if field := evidenceField(finding.Match, finding.RuleID); field != "" {
			covered[evidenceKey(finding, field)] = true
		}
	}
	out := make([]Finding, 0, len(in))
	for _, finding := range in {
		field := evidenceField(finding.Match, finding.RuleID)
		if strings.Contains(finding.RuleID, "-R") && field != "" && covered[evidenceKey(finding, field)] {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func evidenceKey(finding Finding, field string) string {
	return finding.OWASPMCP + "\x00" + finding.Resource + "\x00" + field
}

func evidenceField(match, ruleID string) string {
	if field := explicitField(match); field != "" {
		return field
	}
	switch ruleID {
	case "MCP03-301", "MCP03-302", "MCP03-R02":
		return "schema"
	}
	lower := strings.ToLower(match)
	switch {
	case strings.Contains(lower, "pattern="):
		return "description"
	case strings.Contains(lower, "permission"):
		return "permission"
	case strings.Contains(lower, "env="), strings.Contains(lower, "header="), strings.Contains(lower, "auth.token"), strings.Contains(lower, "auth.apikey"):
		return "secret"
	case strings.Contains(lower, "uri="), strings.Contains(lower, "url="):
		return "uri"
	case strings.Contains(lower, "logging"), strings.Contains(lower, "audit"):
		return "logging"
	case strings.Contains(lower, "auth."):
		return "auth"
	case strings.Contains(lower, "arg"), strings.Contains(lower, "command"):
		return "command"
	case strings.Contains(lower, "tool="):
		return "tool"
	case strings.Contains(lower, "path="):
		return pathField(lower)
	default:
		return ""
	}
}

func explicitField(match string) string {
	lower := strings.ToLower(match)
	const marker = "field="
	index := strings.Index(lower, marker)
	if index < 0 {
		return ""
	}
	rest := lower[index+len(marker):]
	if cut := strings.IndexAny(rest, " \t"); cut >= 0 {
		return rest[:cut]
	}
	return rest
}

func withField(field, match string) string {
	if field == "" {
		return match
	}
	return "field=" + field + " " + match
}

func pathField(match string) string {
	switch {
	case strings.Contains(match, "description"):
		return "description"
	case strings.Contains(match, "permission"):
		return "permission"
	case strings.Contains(match, ".env"), strings.Contains(match, "env"):
		return "secret"
	case strings.Contains(match, "url"), strings.Contains(match, "uri"):
		return "uri"
	case strings.Contains(match, "logging"), strings.Contains(match, "audit"):
		return "logging"
	case strings.Contains(match, "auth"):
		return "auth"
	case strings.Contains(match, "args"), strings.Contains(match, "command"):
		return "command"
	case strings.Contains(match, "inputschema"), strings.Contains(match, "tools"):
		return "schema"
	default:
		return ""
	}
}
