package scanner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdataDir returns the absolute path to the project's testdata directory.
func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata")
}

// ---------------------------------------------------------------------------
// Integration: Vulnerable Server
// ---------------------------------------------------------------------------

func TestScanVulnerableServer(t *testing.T) {
	s := New()
	result, err := s.ScanFile(filepath.Join(testdataDir(), "vulnerable-server.json"))
	require.NoError(t, err, "ScanFile should not return an error")
	require.NotNil(t, result)

	// Collect all OWASP MCP categories found.
	owaspCategories := make(map[string]bool)
	for _, f := range result.Findings {
		owaspCategories[f.OWASPMCP] = true
	}

	expectedCategories := []string{
		"MCP01", // Prompt Injection
		"MCP02", // Excessive Permissions
		"MCP03", // Missing Auth
		"MCP04", // Secrets Exposure
		"MCP05", // Unsafe Resources
		"MCP06", // Tool Spoofing
		"MCP07", // Insecure Transport
		"MCP08", // Unvalidated Schemas
		"MCP09", // Audit Logging
		"MCP10", // Resource Exhaustion
	}

	for _, cat := range expectedCategories {
		assert.True(t, owaspCategories[cat], "expected findings for OWASP MCP category %s", cat)
	}

	// Verify the target is set correctly.
	assert.Equal(t, "vulnerable-server.json", result.Target)

	// Verify we have a reasonable number of findings (15 after dedup).
	assert.GreaterOrEqual(t, len(result.Findings), 10, "vulnerable server should produce at least 10 findings")
}

// ---------------------------------------------------------------------------
// DXT Manifest Support
// ---------------------------------------------------------------------------

func TestScanDXTManifest(t *testing.T) {
	s := New()
	result, err := s.ScanFile(filepath.Join(testdataDir(), "dxt-manifest.json"))
	require.NoError(t, err)
	require.NotNil(t, result)

	// DXT manifest has secrets in env, no auth, no perms, no schema, no logging, no rate limit
	assert.NotEmpty(t, result.Findings, "DXT manifest should produce findings")

	// Should auto-detect the DXT format and use display_name
	owaspCategories := make(map[string]bool)
	for _, f := range result.Findings {
		owaspCategories[f.OWASPMCP] = true
	}
	assert.True(t, owaspCategories["MCP03"], "should detect missing auth")
	assert.True(t, owaspCategories["MCP04"], "should detect secrets in env")

	// Verify the resource name uses the display_name from DXT
	for _, f := range result.Findings {
		assert.Contains(t, f.Resource, "Test Extension", "resource should use DXT display_name")
	}
}

func TestScanDXTFormatFlag(t *testing.T) {
	s := New()
	s.InputFormat = FormatDXT
	result, err := s.ScanFile(filepath.Join(testdataDir(), "dxt-manifest.json"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Findings, "explicit DXT format should produce findings")
}

// ---------------------------------------------------------------------------
// Integration: Safe Server
// ---------------------------------------------------------------------------

func TestScanSafeServer(t *testing.T) {
	s := New()
	result, err := s.ScanFile(filepath.Join(testdataDir(), "safe-server.json"))
	require.NoError(t, err, "ScanFile should not return an error")
	require.NotNil(t, result)

	assert.Empty(t, result.Findings, "safe server should produce zero findings")
	assert.Equal(t, "safe-server.json", result.Target)
}

// ---------------------------------------------------------------------------
// Severity Filter
// ---------------------------------------------------------------------------

func TestSeverityFilter(t *testing.T) {
	tests := []struct {
		name             string
		severity         []string
		expectFindings   bool
		allowedSeverity  string
		forbiddenSeverity string
	}{
		{
			name:              "filter critical only",
			severity:          []string{"critical"},
			expectFindings:    true,
			allowedSeverity:   "critical",
			forbiddenSeverity: "medium",
		},
		{
			name:              "filter medium only",
			severity:          []string{"medium"},
			expectFindings:    true,
			allowedSeverity:   "medium",
			forbiddenSeverity: "critical",
		},
		{
			name:            "filter high and critical",
			severity:        []string{"high", "critical"},
			expectFindings:  true,
			allowedSeverity: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			s.Severity = tt.severity

			result, err := s.ScanFile(filepath.Join(testdataDir(), "vulnerable-server.json"))
			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.expectFindings {
				require.NotEmpty(t, result.Findings, "expected findings for severity filter %v", tt.severity)
			}

			// Assert all returned findings match the allowed severities.
			for _, f := range result.Findings {
				found := false
				for _, allowed := range tt.severity {
					if f.Severity == allowed {
						found = true
						break
					}
				}
				assert.True(t, found, "finding %s has severity %s which is not in the allowed set %v", f.RuleID, f.Severity, tt.severity)
			}

			// Assert the forbidden severity is not present (when specified).
			if tt.forbiddenSeverity != "" {
				for _, f := range result.Findings {
					assert.NotEqual(t, tt.forbiddenSeverity, f.Severity,
						"finding %s should not have severity %s", f.RuleID, tt.forbiddenSeverity)
				}
			}
		})
	}
}
