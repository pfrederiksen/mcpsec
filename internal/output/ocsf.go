package output

import (
	"encoding/json"
	"io"
	"time"
)

var severityMap = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

// OCSFEvent represents an OCSF Security Finding (class_uid 2001).
type OCSFEvent struct {
	ClassUID    int            `json:"class_uid"`
	CategoryUID int           `json:"category_uid"`
	ActivityID  int            `json:"activity_id"`
	SeverityID  int            `json:"severity_id"`
	Severity    string         `json:"severity"`
	Time        int64          `json:"time"`
	Finding     OCSFFinding    `json:"finding"`
	Resources   []OCSFResource `json:"resources"`
	Metadata    OCSFMetadata   `json:"metadata"`
}

type OCSFFinding struct {
	UID         string          `json:"uid"`
	Title       string          `json:"title"`
	Desc        string          `json:"desc"`
	Remediation OCSFRemediation `json:"remediation"`
}

type OCSFRemediation struct {
	Desc string `json:"desc"`
}

type OCSFResource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type OCSFMetadata struct {
	Product OCSFProduct `json:"product"`
	Version string      `json:"version"`
}

type OCSFProduct struct {
	Name string `json:"name"`
}

// FindingInput is the data needed to produce an OCSF event.
type FindingInput struct {
	RuleID      string
	Name        string
	Severity    string
	Description string
	Remediation string
	Resource    string
}

// WriteOCSF writes findings as OCSF JSON to the given writer.
func WriteOCSF(w io.Writer, findings []FindingInput, version string) error {
	events := make([]OCSFEvent, 0, len(findings))
	now := time.Now().Unix()

	for _, f := range findings {
		events = append(events, OCSFEvent{
			ClassUID:    2001,
			CategoryUID: 2,
			ActivityID:  1,
			SeverityID:  severityMap[f.Severity],
			Severity:    f.Severity,
			Time:        now,
			Finding: OCSFFinding{
				UID:   f.RuleID,
				Title: f.Name,
				Desc:  f.Description,
				Remediation: OCSFRemediation{
					Desc: f.Remediation,
				},
			},
			Resources: []OCSFResource{
				{Type: "MCP Server", Name: f.Resource},
			},
			Metadata: OCSFMetadata{
				Product: OCSFProduct{Name: "MCPSec Audit"},
				Version: version,
			},
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(events)
}
