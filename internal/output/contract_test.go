package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOCSFEventsMatchDashboardContract(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dashboard, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "splunk", "dashboards", "mcp_security_posture.xml"))
	require.NoError(t, err)
	paths := regexp.MustCompile(`spath output=\S+ path=([^\s<]+)`).FindAllStringSubmatch(string(dashboard), -1)
	require.NotEmpty(t, paths)

	event := newOCSFEvent(FindingInput{
		RuleID: "MCP01-101", Name: "Plain-text secret", Severity: "critical",
		Description: "A secret is present.", Remediation: "Remove it.",
		Resource: "mcpserver:demo", OWASPMCP: "MCP01",
	}, "test", 1)
	raw, err := json.Marshal(event)
	require.NoError(t, err)
	var doc any
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, 200101, event.TypeUID)

	seen := map[string]bool{}
	for _, match := range paths {
		path := match[1]
		if seen[path] {
			continue
		}
		seen[path] = true
		assert.Truef(t, resolvePath(doc, path), "dashboard path %s is missing from the OCSF event", path)
	}
}

func resolvePath(doc any, path string) bool {
	path = regexp.MustCompile(`\{\}`).ReplaceAllString(path, "")
	current := doc
	for _, part := range regexp.MustCompile(`\.`).Split(path, -1) {
		if part == "" {
			continue
		}
		switch node := current.(type) {
		case map[string]any:
			next, found := node[part]
			if !found {
				return false
			}
			current = next
		case []any:
			if len(node) == 0 {
				return false
			}
			item, isMap := node[0].(map[string]any)
			if !isMap {
				return false
			}
			next, found := item[part]
			if !found {
				return false
			}
			current = next
		default:
			return false
		}
	}
	return current != nil && current != ""
}
