package output

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// SplunkHECEvent is the wrapper for Splunk HTTP Event Collector.
type SplunkHECEvent struct {
	Time       int64       `json:"time"`
	Source     string      `json:"source"`
	Sourcetype string     `json:"sourcetype"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

// WriteSplunk sends findings to a Splunk HEC endpoint.
func WriteSplunk(findings []FindingInput, version, hecURL, hecToken, index string) error {
	now := time.Now().Unix()

	for _, f := range findings {
		event := SplunkHECEvent{
			Time:       now,
			Source:     "mcpsec",
			Sourcetype: "_json",
			Index:      index,
			Event: OCSFEvent{
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
			},
		}

		body, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshaling event: %w", err)
		}

		if err := sendToHEC(hecURL, hecToken, body); err != nil {
			return err
		}
	}
	return nil
}

// WriteSplunkToWriter writes Splunk HEC-formatted events to a writer (for file output).
func WriteSplunkToWriter(w io.Writer, findings []FindingInput, version string) error {
	now := time.Now().Unix()
	enc := json.NewEncoder(w)

	for _, f := range findings {
		event := SplunkHECEvent{
			Time:       now,
			Source:     "mcpsec",
			Sourcetype: "_json",
			Event: OCSFEvent{
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
			},
		}
		if err := enc.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

// ValidateHECURL checks that a Splunk HEC URL uses HTTPS.
func ValidateHECURL(hecURL string) error {
	parsed, err := url.Parse(hecURL)
	if err != nil {
		return fmt.Errorf("invalid HEC URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("HEC URL must use HTTPS (got %q)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("HEC URL must include a host")
	}
	return nil
}

func sendToHEC(hecURL, hecToken string, body []byte) (retErr error) {
	if err := ValidateHECURL(hecURL); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", hecURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating HEC request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+hecToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending to HEC: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if readErr != nil {
			return fmt.Errorf("HEC returned status %d (could not read response body)", resp.StatusCode)
		}
		return fmt.Errorf("HEC returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
