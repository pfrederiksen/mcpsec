package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateIsScopedToOneServer(t *testing.T) {
	engine := &Engine{Rules: []*Rule{{
		ID: "TEST-001", Name: "Danger", Severity: "high", OWASPMCP: "MCP01",
		Match: MatchDef{Type: "regex", Pattern: "dangerous"},
	}}}
	assert.Len(t, engine.Evaluate("bad", map[string]interface{}{"description": "dangerous"}), 1)
	assert.Empty(t, engine.Evaluate("good", map[string]interface{}{"description": "ordinary"}))
}

func TestEvaluateJSONPathSelectsValues(t *testing.T) {
	engine := &Engine{Rules: []*Rule{{
		ID: "TEST-002", Name: "Secret", Severity: "critical", OWASPMCP: "MCP04",
		Match: MatchDef{Type: "jsonpath", Path: "$.mcpServers.*.env[*]", Pattern: `sk-[a-z0-9]+`},
	}}}
	server := map[string]interface{}{"env": map[string]interface{}{"API_KEY": "sk-abcdefghijklmnop"}, "description": "sk-not-selected"}
	findings := engine.Evaluate("one", server)
	require.Len(t, findings, 1)
	assert.Equal(t, "path=$.m***", findings[0].Match)

	server = map[string]interface{}{"description": "sk-not-selected"}
	assert.Empty(t, engine.Evaluate("two", server))
}

func TestJSONPathRecursiveDescent(t *testing.T) {
	root := map[string]interface{}{"tools": []interface{}{map[string]interface{}{"env": "one"}}, "env": "two"}
	assert.ElementsMatch(t, []interface{}{"one", "two"}, jsonPathValues(root, "$..env"))
}
