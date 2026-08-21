package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaselineDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"mcpServers":{"approved":{"command":"node","args":["server.js"]}}}`), 0o600))
	s := New()
	require.NoError(t, s.CreateBaseline(configPath, baselinePath))
	s.BaselinePath = baselinePath
	clean, err := s.ScanFile(configPath)
	require.NoError(t, err)
	assert.NotContains(t, findingRuleIDs(clean.Findings), "MCP03-201")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"mcpServers":{"approved":{"command":"node","args":["changed.js"]}}}`), 0o600))
	drifted, err := s.ScanFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, findingRuleIDs(drifted.Findings), "MCP03-201")
}

func TestDiscoveryAndShadowPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"mcpServers":{"approved":{"command":"node"},"rogue":{"command":"python"}}}`), 0o600))
	found, err := New().Discover([]string{dir})
	require.NoError(t, err)
	require.Len(t, found, 1)
	findings := ShadowFindings(found, []string{"approved"})
	require.Len(t, findings, 1)
	assert.Equal(t, "MCP09", findings[0].OWASPMCP)
	assert.Equal(t, "mcpserver:rogue", findings[0].Resource)
}

func TestActiveScanOnlyEnumeratesTools(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		methods = append(methods, request.Method)
		if request.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if request.Method == "initialize" {
			_, writeErr := w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"test","version":"1"}}}`))
			assert.NoError(t, writeErr)
			return
		}
		_, writeErr := w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"safe","description":"Read a record","inputSchema":{"type":"object"}}]}}`))
		assert.NoError(t, writeErr)
	}))
	defer server.Close()
	result, err := New().ActiveScan(context.Background(), server.URL, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"initialize", "notifications/initialized", "tools/list"}, methods)
	assert.Contains(t, findingRuleIDs(result.Findings), "MCP07-201")
}

func TestSourceScan(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "server.py"), []byte("os.system(params.command)\nrequests.get(input.url)\n"), 0o600))
	result, err := New().ScanSource(dir)
	require.NoError(t, err)
	assert.Contains(t, findingRuleIDs(result.Findings), "MCP05-301")
	assert.Contains(t, findingRuleIDs(result.Findings), "MCP05-303")
}

func findingRuleIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, finding := range findings {
		ids[i] = finding.RuleID
	}
	return ids
}
