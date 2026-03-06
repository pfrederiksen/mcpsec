package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestWriteOCSF
// ---------------------------------------------------------------------------

func TestWriteOCSF(t *testing.T) {
	tests := []struct {
		name     string
		findings []FindingInput
		version  string
	}{
		{
			name: "single finding produces correct OCSF fields",
			findings: []FindingInput{
				{
					RuleID:      "MCP01-001",
					Name:        "Prompt injection detected",
					Severity:    "high",
					Description: "Tool description contains injection patterns",
					Remediation: "Sanitize tool descriptions",
					Resource:    "mcpserver:test-server",
				},
			},
			version: "1.0.0",
		},
		{
			name: "multiple findings",
			findings: []FindingInput{
				{
					RuleID:      "MCP03-001",
					Name:        "Missing auth",
					Severity:    "critical",
					Description: "No authentication configured",
					Remediation: "Configure auth",
					Resource:    "mcpserver:server-a",
				},
				{
					RuleID:      "MCP10-001",
					Name:        "No rate limit",
					Severity:    "medium",
					Description: "No rate limiting configured",
					Remediation: "Enable rate limiting",
					Resource:    "mcpserver:server-b",
				},
			},
			version: "2.0.0",
		},
		{
			name:     "empty findings produces empty array",
			findings: []FindingInput{},
			version:  "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteOCSF(&buf, tt.findings, tt.version)
			require.NoError(t, err, "WriteOCSF should not return an error")

			var events []OCSFEvent
			err = json.Unmarshal(buf.Bytes(), &events)
			require.NoError(t, err, "output should be valid JSON")

			assert.Len(t, events, len(tt.findings))

			for i, event := range events {
				assert.Equal(t, 2001, event.ClassUID, "class_uid should be 2001 (Security Finding)")
				assert.Equal(t, 2, event.CategoryUID, "category_uid should be 2")
				assert.Equal(t, 1, event.ActivityID, "activity_id should be 1")
				assert.Greater(t, event.Time, int64(0), "time should be positive")
				assert.Equal(t, tt.findings[i].Severity, event.Severity)
				assert.Equal(t, severityMap[tt.findings[i].Severity], event.SeverityID)
				assert.Equal(t, tt.findings[i].RuleID, event.Finding.UID)
				assert.Equal(t, tt.findings[i].Name, event.Finding.Title)
				assert.Equal(t, tt.findings[i].Description, event.Finding.Desc)
				assert.Equal(t, tt.findings[i].Remediation, event.Finding.Remediation.Desc)
				assert.Equal(t, "MCPSec Audit", event.Metadata.Product.Name)
				assert.Equal(t, tt.version, event.Metadata.Version)

				require.Len(t, event.Resources, 1)
				assert.Equal(t, "MCP Server", event.Resources[0].Type)
				assert.Equal(t, tt.findings[i].Resource, event.Resources[0].Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWriteTable
// ---------------------------------------------------------------------------

func TestWriteTable(t *testing.T) {
	tests := []struct {
		name           string
		findings       []FindingInput
		expectColumns  []string
		expectTotal    string
		expectNoFindings bool
	}{
		{
			name: "table contains expected columns and data",
			findings: []FindingInput{
				{
					RuleID:   "MCP01-001",
					Name:     "Prompt injection detected",
					Severity: "high",
					Resource: "mcpserver:test-server",
				},
				{
					RuleID:   "MCP03-001",
					Name:     "Missing auth",
					Severity: "critical",
					Resource: "mcpserver:server-a",
				},
			},
			expectColumns: []string{"RULE ID", "NAME", "SEVERITY", "RESOURCE"},
			expectTotal:   "Total: 2 finding(s)",
		},
		{
			name:             "empty findings shows no findings message",
			findings:         []FindingInput{},
			expectNoFindings: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteTable(&buf, tt.findings)
			assert.NoError(t, err)
			output := buf.String()

			if tt.expectNoFindings {
				assert.Contains(t, output, "No findings.")
				return
			}

			for _, col := range tt.expectColumns {
				assert.Contains(t, output, col, "table output should contain column header %q", col)
			}

			assert.Contains(t, output, tt.expectTotal)

			// Verify finding data appears in the output.
			for _, f := range tt.findings {
				assert.Contains(t, output, f.RuleID, "table should contain rule ID %s", f.RuleID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWriteSplunkToWriter
// ---------------------------------------------------------------------------

func TestWriteSplunkToWriter(t *testing.T) {
	tests := []struct {
		name     string
		findings []FindingInput
		version  string
	}{
		{
			name: "single finding produces valid Splunk HEC event",
			findings: []FindingInput{
				{
					RuleID:      "MCP04-001",
					Name:        "Secret exposure",
					Severity:    "critical",
					Description: "Plain-text secret found",
					Remediation: "Use a secrets manager",
					Resource:    "mcpserver:test-server",
				},
			},
			version: "1.0.0",
		},
		{
			name: "multiple findings produce one event per finding",
			findings: []FindingInput{
				{
					RuleID:      "MCP07-001",
					Name:        "Insecure transport",
					Severity:    "high",
					Description: "HTTP transport used",
					Remediation: "Use HTTPS",
					Resource:    "mcpserver:server-a",
				},
				{
					RuleID:      "MCP09-001",
					Name:        "No logging",
					Severity:    "medium",
					Description: "Logging not configured",
					Remediation: "Enable logging",
					Resource:    "mcpserver:server-b",
				},
			},
			version: "2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteSplunkToWriter(&buf, tt.findings, tt.version)
			require.NoError(t, err, "WriteSplunkToWriter should not return an error")

			// Each finding produces one JSON line.
			decoder := json.NewDecoder(&buf)
			for i := 0; i < len(tt.findings); i++ {
				var event SplunkHECEvent
				err := decoder.Decode(&event)
				require.NoError(t, err, "each line should be valid JSON")

				assert.Equal(t, "mcpsec", event.Source)
				assert.Equal(t, "_json", event.Sourcetype)
				assert.Greater(t, event.Time, int64(0), "time should be positive")

				// The Event field is an interface{} that decodes as map[string]interface{}.
				eventMap, ok := event.Event.(map[string]interface{})
				require.True(t, ok, "event.Event should be a JSON object")

				assert.Equal(t, float64(2001), eventMap["class_uid"])
				assert.Equal(t, tt.findings[i].Severity, eventMap["severity"])

				// Verify nested finding fields.
				findingMap, ok := eventMap["finding"].(map[string]interface{})
				require.True(t, ok, "event should contain a finding object")
				assert.Equal(t, tt.findings[i].RuleID, findingMap["uid"])
				assert.Equal(t, tt.findings[i].Name, findingMap["title"])

				// Verify metadata.
				metaMap, ok := eventMap["metadata"].(map[string]interface{})
				require.True(t, ok, "event should contain metadata")
				productMap, ok := metaMap["product"].(map[string]interface{})
				require.True(t, ok, "metadata should contain product")
				assert.Equal(t, "MCPSec Audit", productMap["name"])
				assert.Equal(t, tt.version, metaMap["version"])
			}
		})
	}
}
