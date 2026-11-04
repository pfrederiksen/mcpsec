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
	runs := report["runs"].([]any)
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	assert.Equal(t, "MCP05-301", rules[0].(map[string]any)["id"])
	results := run["results"].([]any)
	result := results[0].(map[string]any)
	assert.Equal(t, "error", result["level"])
	location := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	assert.Equal(t, "server.py", location["artifactLocation"].(map[string]any)["uri"])
	assert.Equal(t, float64(12), location["region"].(map[string]any)["startLine"])
}
