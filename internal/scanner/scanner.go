package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pfrederiksen/mcpsec/internal/checks"
	"github.com/pfrederiksen/mcpsec/internal/rules"
)

// Finding represents a single security finding from a scan.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	OWASPMCP    string `json:"owasp_mcp"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Resource    string `json:"resource"`
	Match       string `json:"match,omitempty"`
}

// ScanResult holds all findings from a scan.
type ScanResult struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
}

// InputFormat specifies the config file format.
type InputFormat string

const (
	FormatAuto       InputFormat = "auto"
	FormatMCPServers InputFormat = "mcpservers"
	FormatDXT        InputFormat = "dxt"
	FormatDXTDir     InputFormat = "dxtdir"
)

const maxConfigSize = 10 << 20

// MCPServerConfig represents a parsed MCP server configuration file.
type MCPServerConfig struct {
	MCPServers map[string]MCPServer `json:"mcpServers"`
	Servers    map[string]MCPServer `json:"servers,omitempty"`
}

// DXTManifest represents a Claude Desktop Extension manifest.json.
type DXTManifest struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Server      DXTServer `json:"server"`
	Tools       []Tool    `json:"tools"`
}

// DXTServer holds the server configuration within a DXT manifest.
type DXTServer struct {
	Type       string    `json:"type"`
	EntryPoint string    `json:"entry_point"`
	MCPConfig  MCPServer `json:"mcp_config"`
}

// MCPServer represents a single MCP server definition.
type MCPServer struct {
	Command        string           `json:"command"`
	Args           []string         `json:"args"`
	URL            string           `json:"url,omitempty"`
	Transport      string           `json:"transport,omitempty"`
	Environment    StringMap        `json:"env,omitempty"`
	Headers        StringMap        `json:"headers,omitempty"`
	CWD            string           `json:"cwd,omitempty"`
	EnvFile        string           `json:"envFile,omitempty"`
	SandboxEnabled *bool            `json:"sandboxEnabled,omitempty"`
	Tools          []Tool           `json:"tools,omitempty"`
	Auth           *AuthConfig      `json:"auth,omitempty"`
	TLS            *TLSConfig       `json:"tls,omitempty"`
	Schema         *SchemaConfig    `json:"schema,omitempty"`
	Logging        *LoggingConfig   `json:"logging,omitempty"`
	RateLimit      *RateLimitConfig `json:"rateLimit,omitempty"`
	Permissions    []string         `json:"permissions,omitempty"`
}

// Tool represents a tool definition within an MCP server.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Environment StringMap       `json:"env,omitempty"`
	URI         string          `json:"uri,omitempty"`
	Permissions []string        `json:"permissions,omitempty"`
	Hash        string          `json:"hash,omitempty"`
}

// StringMap accepts the string, numeric, boolean, and null environment values
// permitted by clients such as VS Code while presenting checks with strings.
type StringMap map[string]string

func (m *StringMap) UnmarshalJSON(data []byte) error {
	var values map[string]any
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	result := make(StringMap, len(values))
	for key, value := range values {
		switch typed := value.(type) {
		case string:
			result[key] = typed
		case nil:
			result[key] = ""
		default:
			result[key] = fmt.Sprint(typed)
		}
	}
	*m = result
	return nil
}

// AuthConfig holds authentication configuration for an MCP server.
type AuthConfig struct {
	Type             string   `json:"type,omitempty"`
	Token            string   `json:"token,omitempty"`
	APIKey           string   `json:"apiKey,omitempty"`
	Audience         string   `json:"audience,omitempty"`
	Resource         string   `json:"resource,omitempty"`
	PKCE             *bool    `json:"pkce,omitempty"`
	TokenPassthrough bool     `json:"tokenPassthrough,omitempty"`
	RedirectURI      string   `json:"redirectUri,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
}

// TLSConfig holds TLS configuration for an MCP server.
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	MinVer   string `json:"minVersion,omitempty"`
}

// SchemaConfig holds schema validation configuration.
type SchemaConfig struct {
	ValidateInput  bool `json:"validateInput"`
	ValidateOutput bool `json:"validateOutput"`
}

// LoggingConfig holds logging/audit configuration.
type LoggingConfig struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level,omitempty"`
	Audit   bool   `json:"audit"`
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled    bool `json:"enabled"`
	MaxRPS     int  `json:"maxRequestsPerSecond,omitempty"`
	MaxPayload int  `json:"maxPayloadBytes,omitempty"`
}

// Scanner orchestrates security checks against MCP server configurations.
type Scanner struct {
	RuleEngine   *rules.Engine
	Checks       []checks.Check
	Severity     []string
	InputFormat  InputFormat
	BaselinePath string
	ActiveToken  string
}

// New creates a Scanner with all built-in checks registered.
func New() *Scanner {
	return &Scanner{
		RuleEngine: rules.NewEngine(),
		Checks: []checks.Check{
			&checks.PromptInjectionCheck{},
			&checks.IntentFlowCheck{},
			&checks.StartupCommandCheck{},
			&checks.SupplyChainCheck{},
			&checks.ContextExposureCheck{},
			&checks.PermissionsCheck{},
			&checks.AuthCheck{},
			&checks.SecretsCheck{},
			&checks.UnsafeResourceCheck{},
			&checks.ToolSpoofingCheck{},
			&checks.TransportCheck{},
			&checks.SchemaCheck{},
			&checks.AuditLoggingCheck{},
		},
	}
}

// LoadRules loads YAML rules from a directory into the rule engine.
func (s *Scanner) LoadRules(dir string) error {
	return s.RuleEngine.LoadFromDirectory(dir)
}

// ScanFile parses an MCP server config file and runs all checks.
// It auto-detects the format (mcpServers JSON vs DXT manifest) unless
// InputFormat is explicitly set.
func (s *Scanner) ScanFile(path string) (*ScanResult, error) {
	format := s.InputFormat
	if format == "" {
		format = FormatAuto
	}

	// Handle DXT directory scanning (e.g., Claude Extensions dir)
	if format == FormatDXTDir {
		return s.scanDXTDirectory(path)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Auto-detect: if path is a directory, treat as DXT extensions dir
	if info.IsDir() && format == FormatAuto {
		return s.scanDXTDirectory(path)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("expected a config file, got directory: %s", path)
	}
	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("config file exceeds %d byte limit", maxConfigSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	config, err := s.parseConfig(data, path, format)
	if err != nil {
		return nil, err
	}

	result, err := s.scanConfig(config, data, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if s.BaselinePath != "" {
		drift, compareErr := compareBaseline(config, s.BaselinePath)
		if compareErr != nil {
			return nil, compareErr
		}
		for _, finding := range drift {
			if s.severityAllowed(finding.Severity) {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
	return result, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, delimOK := token.(json.Delim)
	if !delimOK {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return fmt.Errorf("invalid object key")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if inspectErr := inspectJSONValue(decoder); inspectErr != nil {
				return inspectErr
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if inspectErr := inspectJSONValue(decoder); inspectErr != nil {
				return inspectErr
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return nil
	}
}

// parseConfig parses data into MCPServerConfig, auto-detecting format if needed.
func (s *Scanner) parseConfig(data []byte, path string, format InputFormat) (*MCPServerConfig, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if format == FormatDXT {
		return parseDXTManifest(data)
	}

	if format == FormatMCPServers {
		var config MCPServerConfig
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
		config.normalizeServers()
		if len(config.MCPServers) == 0 {
			return nil, fmt.Errorf("parsing config file: no MCP servers found")
		}
		return &config, nil
	}

	// Auto-detect: try mcpServers first, then DXT
	var config MCPServerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if len(config.MCPServers) > 0 {
		return &config, nil
	}
	if len(config.Servers) > 0 {
		config.normalizeServers()
		return &config, nil
	}

	// Check if it looks like a DXT manifest
	var probe struct {
		DXTVersion string `json:"dxt_version"`
		Name       string `json:"name"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.DXTVersion != "" {
		return parseDXTManifest(data)
	}

	return nil, fmt.Errorf("unsupported config format: expected a non-empty mcpServers object or DXT manifest")
}

func (c *MCPServerConfig) normalizeServers() {
	if len(c.MCPServers) == 0 && len(c.Servers) > 0 {
		c.MCPServers = c.Servers
	}
}

// parseDXTManifest converts a DXT manifest.json into MCPServerConfig.
func parseDXTManifest(data []byte) (*MCPServerConfig, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("parsing DXT manifest: %w", err)
	}
	var manifest DXTManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing DXT manifest: %w", err)
	}

	name := manifest.DisplayName
	if name == "" {
		name = manifest.Name
	}
	if name == "" {
		return nil, fmt.Errorf("parsing DXT manifest: missing name or display_name")
	}

	server := manifest.Server.MCPConfig
	// Merge top-level tools into the server if the server has none
	if len(server.Tools) == 0 && len(manifest.Tools) > 0 {
		server.Tools = manifest.Tools
	}

	return &MCPServerConfig{
		MCPServers: map[string]MCPServer{
			name: server,
		},
	}, nil
}

// scanDXTDirectory scans all DXT manifest.json files in a directory.
func (s *Scanner) scanDXTDirectory(dir string) (*ScanResult, error) {
	result := &ScanResult{
		Target: filepath.Base(dir),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading DXT directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(dir, entry.Name(), "manifest.json")
		manifestInfo, err := os.Stat(manifestPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading DXT manifest %s: %w", entry.Name(), err)
		}
		if manifestInfo.Size() > maxConfigSize {
			return nil, fmt.Errorf("DXT manifest %s exceeds %d byte limit", entry.Name(), maxConfigSize)
		}
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading DXT manifest %s: %w", entry.Name(), err)
		}
		config, err := parseDXTManifest(data)
		if err != nil {
			return nil, fmt.Errorf("parsing DXT manifest %s: %w", entry.Name(), err)
		}

		sub, err := s.scanConfig(config, data, entry.Name())
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: error scanning %s: %v\n", entry.Name(), err)
			continue
		}
		result.Findings = append(result.Findings, sub.Findings...)
	}

	return result, nil
}

// scanConfig runs all checks against a parsed MCPServerConfig.
func (s *Scanner) scanConfig(config *MCPServerConfig, rawData []byte, target string) (*ScanResult, error) {
	result := &ScanResult{
		Target: target,
	}

	serverNames := make([]string, 0, len(config.MCPServers))
	for serverName := range config.MCPServers {
		serverNames = append(serverNames, serverName)
	}
	sort.Strings(serverNames)
	for _, serverName := range serverNames {
		server := config.MCPServers[serverName]
		ctx := checks.CheckContext{
			ServerName: serverName,
			Server:     toCheckServer(server),
			RawConfig:  rawData,
		}

		for _, check := range s.Checks {
			findings := check.Run(ctx)
			for _, f := range findings {
				if s.severityAllowed(f.Severity) {
					result.Findings = append(result.Findings, Finding{
						RuleID:      f.RuleID,
						Name:        f.Name,
						Severity:    f.Severity,
						OWASPMCP:    f.OWASPMCP,
						Description: f.Description,
						Remediation: f.Remediation,
						Resource:    fmt.Sprintf("mcpserver:%s", serverName),
						Match:       f.Match,
					})
				}
			}
		}

		// Also run YAML rule engine checks
		ruleFindings := s.RuleEngine.Evaluate(serverName, server)
		for _, f := range ruleFindings {
			if s.severityAllowed(f.Severity) {
				result.Findings = append(result.Findings, Finding{
					RuleID:      f.RuleID,
					Name:        f.Name,
					Severity:    f.Severity,
					OWASPMCP:    f.OWASPMCP,
					Description: f.Description,
					Remediation: f.Remediation,
					Resource:    fmt.Sprintf("mcpserver:%s", serverName),
					Match:       f.Match,
				})
			}
		}
	}

	return result, nil
}

func (s *Scanner) severityAllowed(sev string) bool {
	if len(s.Severity) == 0 {
		return true
	}
	sev = strings.ToLower(sev)
	for _, allowed := range s.Severity {
		if strings.ToLower(allowed) == sev {
			return true
		}
	}
	return false
}

func toCheckServer(s MCPServer) checks.ServerConfig {
	cs := checks.ServerConfig{
		Command:        s.Command,
		Args:           s.Args,
		URL:            s.URL,
		Transport:      s.Transport,
		Environment:    map[string]string(s.Environment),
		Headers:        map[string]string(s.Headers),
		CWD:            s.CWD,
		EnvFile:        s.EnvFile,
		SandboxEnabled: s.SandboxEnabled,
		Permissions:    s.Permissions,
	}
	if s.Auth != nil {
		cs.Auth = &checks.AuthConfig{Type: s.Auth.Type, Token: s.Auth.Token, APIKey: s.Auth.APIKey, Audience: s.Auth.Audience, Resource: s.Auth.Resource, PKCE: s.Auth.PKCE, TokenPassthrough: s.Auth.TokenPassthrough, RedirectURI: s.Auth.RedirectURI, Scopes: s.Auth.Scopes}
	}
	if s.TLS != nil {
		cs.TLS = &checks.TLSConfig{Enabled: s.TLS.Enabled, CertFile: s.TLS.CertFile, KeyFile: s.TLS.KeyFile, MinVer: s.TLS.MinVer}
	}
	if s.Schema != nil {
		cs.Schema = &checks.SchemaConfig{ValidateInput: s.Schema.ValidateInput, ValidateOutput: s.Schema.ValidateOutput}
	}
	if s.Logging != nil {
		cs.Logging = &checks.LoggingConfig{Enabled: s.Logging.Enabled, Level: s.Logging.Level, Audit: s.Logging.Audit}
	}
	if s.RateLimit != nil {
		cs.RateLimit = &checks.RateLimitConfig{Enabled: s.RateLimit.Enabled, MaxRPS: s.RateLimit.MaxRPS, MaxPayload: s.RateLimit.MaxPayload}
	}
	for _, t := range s.Tools {
		cs.Tools = append(cs.Tools, checks.ToolConfig{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
			Environment: map[string]string(t.Environment),
			URI:         t.URI,
			Permissions: t.Permissions,
			Hash:        t.Hash,
		})
	}
	return cs
}
