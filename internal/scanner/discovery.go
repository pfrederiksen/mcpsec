package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type DiscoveredConfig struct {
	Path    string   `json:"path"`
	Clients []string `json:"clients"`
	Servers []string `json:"servers"`
}

// DefaultDiscoveryPaths returns established per-user MCP client config locations.
func DefaultDiscoveryPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	paths := []string{
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		filepath.Join(home, ".copilot", "mcp-config.json"),
	}
	if cwd, cwdErr := os.Getwd(); cwdErr == nil {
		paths = append(paths, filepath.Join(cwd, ".vscode", "mcp.json"), filepath.Join(cwd, ".mcp.json"))
	}
	if runtime.GOOS == "darwin" {
		paths = append(paths,
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
		)
	} else if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			paths = append(paths, filepath.Join(appData, "Claude", "claude_desktop_config.json"), filepath.Join(appData, "Code", "User", "mcp.json"))
		}
	} else {
		paths = append(paths, filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), filepath.Join(home, ".config", "Code", "User", "mcp.json"))
	}
	return paths
}

// Discover inventories valid MCP configurations without executing any server.
func (s *Scanner) Discover(paths []string) ([]DiscoveredConfig, error) {
	if len(paths) == 0 {
		paths = DefaultDiscoveryPaths()
	}
	found := make([]DiscoveredConfig, 0)
	for _, path := range paths {
		clean := filepath.Clean(path)
		info, err := os.Stat(clean)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		candidates := []string{clean}
		if info.IsDir() {
			candidates = nil
			err = filepath.WalkDir(clean, func(candidate string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					if candidate != clean && (strings.HasPrefix(entry.Name(), ".git") || entry.Name() == "node_modules") {
						return filepath.SkipDir
					}
					return nil
				}
				name := strings.ToLower(entry.Name())
				if name == "mcp.json" || name == ".mcp.json" || name == "mcp-config.json" || name == "mcp_config.json" || name == "claude_desktop_config.json" {
					candidates = append(candidates, candidate)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("discovering %s: %w", clean, err)
			}
		}
		for _, candidate := range candidates {
			data, readErr := os.ReadFile(candidate)
			if readErr != nil {
				return nil, readErr
			}
			config, parseErr := s.parseConfig(data, candidate, FormatAuto)
			if parseErr != nil {
				continue
			}
			servers := make([]string, 0, len(config.MCPServers))
			for name := range config.MCPServers {
				servers = append(servers, name)
			}
			sort.Strings(servers)
			clients := inferClients(candidate)
			found = append(found, DiscoveredConfig{Path: candidate, Clients: clients, Servers: servers})
		}
	}
	return found, nil
}

// ShadowFindings compares discovered inventory with an explicit approved-server allowlist.
func ShadowFindings(discovered []DiscoveredConfig, approved []string) []Finding {
	allow := make(map[string]bool, len(approved))
	for _, name := range approved {
		allow[strings.ToLower(strings.TrimSpace(name))] = true
	}
	var findings []Finding
	for _, config := range discovered {
		for _, server := range config.Servers {
			if !allow[strings.ToLower(server)] {
				findings = append(findings, Finding{RuleID: "MCP09-101", Name: "Unapproved shadow MCP server", Severity: "high", OWASPMCP: "MCP09", Description: "A configured MCP server is absent from the supplied approved inventory.", Remediation: "Review ownership and provenance, then remove the server or add it to the governed inventory.", Resource: "mcpserver:" + server, Match: config.Path})
			}
		}
	}
	return findings
}

func inferClients(path string) []string {
	lower := strings.ToLower(path)
	for _, candidate := range []struct{ needle, client string }{{"claude", "Claude Desktop"}, {"cursor", "Cursor"}, {"windsurf", "Windsurf"}, {".vscode", "VS Code"}, {"/code/user/", "VS Code"}, {".copilot", "GitHub Copilot"}} {
		if strings.Contains(lower, candidate.needle) {
			return []string{candidate.client}
		}
	}
	return []string{"Unknown MCP client"}
}
