package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSARIFIncludesRuleAndLine(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, []FindingInput{{
		RuleID: "MCP05-301", Name: "Possible command injection sink", Severity: "high",
		Description: "Review the sink.", Remediation: "Avoid a shell.", OWASPMCP: "MCP05",
		Resource: "source:server.py:12", Location: "server.py", Line: 12,
	}}, "test")
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	assert.Equal(t, "2.1.0", report["version"])
	runs := asSlice(t, report["runs"])
	run := asMap(t, runs[0])
	driver := asMap(t, asMap(t, run["tool"])["driver"])
	rules := asSlice(t, driver["rules"])
	assert.Equal(t, "MCP05-301", asMap(t, rules[0])["id"])
	results := asSlice(t, run["results"])
	result := asMap(t, results[0])
	assert.Equal(t, "error", result["level"])
	location := asMap(t, asMap(t, asSlice(t, result["locations"])[0])["physicalLocation"])
	assert.Equal(t, "server.py", asMap(t, location["artifactLocation"])["uri"])
	assert.Equal(t, float64(12), asMap(t, location["region"])["startLine"])
}

func asMap(t *testing.T, value any) map[string]any {
	t.Helper()
	out, ok := value.(map[string]any)
	require.True(t, ok)
	return out
}

func asSlice(t *testing.T, value any) []any {
	t.Helper()
	out, ok := value.([]any)
	require.True(t, ok)
	return out
}
