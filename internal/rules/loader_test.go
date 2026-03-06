package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestLoadFile
// ---------------------------------------------------------------------------

func TestLoadFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErr     bool
		wantID      string
		wantName    string
		wantSev     string
		wantOWASP   string
		wantMatchTy string
	}{
		{
			name: "valid rule file",
			content: `id: TEST-001
name: Test Rule
severity: high
owasp_mcp: MCP01
description: A test rule for unit testing
remediation: Fix the issue
references:
  - https://example.com/ref1
match:
  type: regex
  pattern: "test-pattern"
`,
			wantErr:     false,
			wantID:      "TEST-001",
			wantName:    "Test Rule",
			wantSev:     "high",
			wantOWASP:   "MCP01",
			wantMatchTy: "regex",
		},
		{
			name: "missing id - should error",
			content: `name: No ID Rule
severity: high
owasp_mcp: MCP01
match:
  type: regex
  pattern: "pattern"
`,
			wantErr: true,
		},
		{
			name: "missing name - should error",
			content: `id: TEST-002
severity: medium
owasp_mcp: MCP02
match:
  type: regex
  pattern: "pattern"
`,
			wantErr: true,
		},
		{
			name: "missing severity - should error",
			content: `id: TEST-003
name: No Severity Rule
owasp_mcp: MCP03
match:
  type: regex
  pattern: "pattern"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "rule.yaml")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			require.NoError(t, err, "failed to write temp rule file")

			rule, err := LoadFile(tmpFile)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, rule)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, rule)
			assert.Equal(t, tt.wantID, rule.ID)
			assert.Equal(t, tt.wantName, rule.Name)
			assert.Equal(t, tt.wantSev, rule.Severity)
			assert.Equal(t, tt.wantOWASP, rule.OWASPMCP)
			assert.Equal(t, tt.wantMatchTy, rule.Match.Type)
		})
	}
}

// ---------------------------------------------------------------------------
// TestValidateRule
// ---------------------------------------------------------------------------

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name       string
		rule       *Rule
		wantErrors int
	}{
		{
			name: "valid rule - no errors",
			rule: &Rule{
				ID:       "VALID-001",
				Name:     "Valid Rule",
				Severity: "high",
				OWASPMCP: "MCP01",
				Match:    MatchDef{Type: "regex", Pattern: ".*"},
			},
			wantErrors: 0,
		},
		{
			name: "invalid rule - missing all required fields",
			rule: &Rule{},
			// Missing: id, name, invalid severity, owasp_mcp, match.type
			wantErrors: 5,
		},
		{
			name: "invalid severity value",
			rule: &Rule{
				ID:       "BAD-SEV",
				Name:     "Bad Severity",
				Severity: "extreme",
				OWASPMCP: "MCP01",
				Match:    MatchDef{Type: "regex"},
			},
			wantErrors: 1,
		},
		{
			name: "invalid match type",
			rule: &Rule{
				ID:       "BAD-MATCH",
				Name:     "Bad Match Type",
				Severity: "medium",
				OWASPMCP: "MCP02",
				Match:    MatchDef{Type: "xpath"},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateRule(tt.rule)
			assert.Len(t, errors, tt.wantErrors, "expected %d validation errors, got %d: %v", tt.wantErrors, len(errors), errors)
		})
	}
}

// ---------------------------------------------------------------------------
// TestLoadDirectory
// ---------------------------------------------------------------------------

func TestLoadDirectory(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		wantCount int
		wantErr   bool
	}{
		{
			name: "multiple valid rule files",
			files: map[string]string{
				"rule1.yaml": `id: DIR-001
name: Rule One
severity: high
owasp_mcp: MCP01
match:
  type: regex
  pattern: "pattern-one"
`,
				"rule2.yml": `id: DIR-002
name: Rule Two
severity: medium
owasp_mcp: MCP02
match:
  type: jsonpath
  path: "$.mcpServers"
  pattern: "pattern-two"
`,
				"rule3.yaml": `id: DIR-003
name: Rule Three
severity: low
owasp_mcp: MCP03
match:
  type: regex
  pattern: "pattern-three"
`,
			},
			wantCount: 3,
			wantErr:   false,
		},
		{
			name: "non-yaml files are skipped",
			files: map[string]string{
				"rule.yaml": `id: ONLY-001
name: Only Rule
severity: high
owasp_mcp: MCP01
match:
  type: regex
  pattern: "only"
`,
				"readme.txt": "This is not a rule file",
				"data.json":  `{"not": "a rule"}`,
			},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "invalid rule in directory causes error",
			files: map[string]string{
				"good.yaml": `id: GOOD-001
name: Good Rule
severity: high
owasp_mcp: MCP01
match:
  type: regex
  pattern: "good"
`,
				"bad.yaml": `name: Missing ID Rule
severity: high
`,
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
				require.NoError(t, err, "failed to write file %s", name)
			}

			rules, err := LoadDirectory(dir)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, rules, tt.wantCount, "expected %d rules loaded", tt.wantCount)

			// Verify each loaded rule has a non-empty ID.
			for _, r := range rules {
				assert.NotEmpty(t, r.ID, "loaded rule should have a non-empty ID")
				assert.NotEmpty(t, r.Name, "loaded rule should have a non-empty Name")
			}
		})
	}
}
