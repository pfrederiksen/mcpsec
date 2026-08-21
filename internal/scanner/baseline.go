package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const baselineVersion = 1

type Baseline struct {
	Version int               `json:"version"`
	Servers map[string]string `json:"servers"`
}

func hashServer(server MCPServer) (string, error) {
	data, err := json.Marshal(server)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// CreateBaseline records immutable fingerprints for every configured server.
func (s *Scanner) CreateBaseline(configPath, outputPath string) error {
	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	config, err := s.parseConfig(data, configPath, FormatAuto)
	if err != nil {
		return err
	}
	baseline := Baseline{Version: baselineVersion, Servers: make(map[string]string, len(config.MCPServers))}
	for name, server := range config.MCPServers {
		baseline.Servers[name], err = hashServer(server)
		if err != nil {
			return fmt.Errorf("fingerprinting %s: %w", name, err)
		}
	}
	out, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(outputPath), append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}
	return nil
}

func compareBaseline(config *MCPServerConfig, path string) ([]Finding, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	if baseline.Version != baselineVersion {
		return nil, fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	var findings []Finding
	for name, server := range config.MCPServers {
		hash, hashErr := hashServer(server)
		if hashErr != nil {
			return nil, hashErr
		}
		previous, exists := baseline.Servers[name]
		switch {
		case !exists:
			findings = append(findings, driftFinding(name, "New MCP server added since baseline", "A server absent from the approved baseline is now configured."))
		case previous != hash:
			findings = append(findings, driftFinding(name, "MCP server configuration changed", "The command, arguments, environment, endpoint, or advertised definitions changed since approval."))
		}
	}
	for name := range baseline.Servers {
		if _, exists := config.MCPServers[name]; !exists {
			findings = append(findings, driftFinding(name, "MCP server removed since baseline", "A server recorded in the approved baseline is no longer configured."))
		}
	}
	return findings, nil
}

func driftFinding(name, title, description string) Finding {
	return Finding{RuleID: "MCP03-201", Name: title, Severity: "high", OWASPMCP: "MCP03", Description: description, Remediation: "Review the change and regenerate the baseline only after approving it.", Resource: "mcpserver:" + name}
}
