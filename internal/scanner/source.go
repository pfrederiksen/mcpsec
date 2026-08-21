package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type sourcePattern struct {
	id, name, severity, owasp, description, remediation string
	re                                                  *regexp.Regexp
}

var sourcePatterns = []sourcePattern{
	{"MCP05-301", "Possible command injection sink", "high", "MCP05", "Untrusted values may reach a shell or process execution API.", "Use direct process execution with fixed arguments and validate inputs.", regexp.MustCompile(`(?i)(exec|system|popen|spawn|command)\s*\([^\n]*(args|input|params|request)`)},
	{"MCP05-302", "Possible path traversal sink", "high", "MCP05", "A request-derived value may be used in a filesystem operation.", "Resolve against an allowlisted root and reject paths that escape it.", regexp.MustCompile(`(?i)(open|readfile|writefile|read_file|write_file)\s*\([^\n]*(args|input|params|request)`)},
	{"MCP05-303", "Possible SSRF sink", "high", "MCP05", "A request-derived URL may be passed to an outbound HTTP client.", "Allowlist schemes and destinations; block private/reserved ranges at connection time.", regexp.MustCompile(`(?i)(fetch|requests\.(get|post)|http\.(get|post)|client\.do)\s*\([^\n]*(args|input|params|request|url)`)},
	{"MCP07-301", "Possible access-token passthrough", "critical", "MCP07", "An inbound Authorization value may be forwarded to an upstream request.", "Exchange for a separately audience-bound upstream token; never pass through the MCP token.", regexp.MustCompile(`(?i)(authorization|access[_-]?token)[^\n]{0,120}(forward|upstream|setheader|headers?\[)`)},
}

var sourceExtensions = map[string]bool{".go": true, ".py": true, ".js": true, ".ts": true, ".tsx": true, ".java": true, ".rs": true}

// ScanSource performs conservative lexical SAST and never builds or executes source.
func (s *Scanner) ScanSource(root string) (*ScanResult, error) {
	result := &ScanResult{Target: filepath.Clean(root)}
	err := filepath.WalkDir(filepath.Clean(root), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !sourceExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		baseName := strings.ToLower(filepath.Base(path))
		if strings.HasSuffix(baseName, "_test.go") || strings.Contains(baseName, ".test.") || strings.HasPrefix(baseName, "test_") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		lineNo := 0
		scan := bufio.NewScanner(file)
		for scan.Scan() {
			lineNo++
			line := scan.Text()
			if strings.Contains(line, "regexp.MustCompile(") {
				continue
			}
			for _, pattern := range sourcePatterns {
				if pattern.re.MatchString(line) && s.severityAllowed(pattern.severity) {
					result.Findings = append(result.Findings, Finding{RuleID: pattern.id, Name: pattern.name, Severity: pattern.severity, OWASPMCP: pattern.owasp, Description: pattern.description, Remediation: pattern.remediation, Resource: fmt.Sprintf("source:%s:%d", path, lineNo), Match: "lexical pattern"})
				}
			}
		}
		return scan.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("scanning source: %w", err)
	}
	return result, nil
}
