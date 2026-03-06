package checks

import "encoding/json"

// CheckFinding is a finding produced by a check.
type CheckFinding struct {
	RuleID      string
	Name        string
	Severity    string
	OWASPMCP    string
	Description string
	Remediation string
	Match       string
}

// Check is the interface all security checks implement.
type Check interface {
	Run(ctx CheckContext) []CheckFinding
}

// CheckContext provides the data a check evaluates against.
type CheckContext struct {
	ServerName string
	Server     ServerConfig
	RawConfig  []byte
}

// ServerConfig mirrors the scanner's MCPServer for use in checks.
type ServerConfig struct {
	Command     string
	Args        []string
	URL         string
	Transport   string
	Environment map[string]string
	Tools       []ToolConfig
	Auth        *AuthConfig
	TLS         *TLSConfig
	Schema      *SchemaConfig
	Logging     *LoggingConfig
	RateLimit   *RateLimitConfig
	Permissions []string
}

type ToolConfig struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Environment map[string]string
	URI         string
	Permissions []string
	Hash        string
}

type AuthConfig struct {
	Type   string
	Token  string
	APIKey string
}

type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	MinVer   string
}

type SchemaConfig struct {
	ValidateInput  bool
	ValidateOutput bool
}

type LoggingConfig struct {
	Enabled bool
	Level   string
	Audit   bool
}

type RateLimitConfig struct {
	Enabled    bool
	MaxRPS     int
	MaxPayload int
}
