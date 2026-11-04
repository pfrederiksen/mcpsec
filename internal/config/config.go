package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the mcpsec policy. Command-line flags override these values.
type Config struct {
	RulesDir       string   `yaml:"rules_dir"`
	Format         string   `yaml:"format"`
	Output         string   `yaml:"output"`
	Severity       []string `yaml:"severity"`
	SplunkURL      string   `yaml:"splunk_url"`
	SplunkToken    string   `yaml:"splunk_token"`
	SplunkIndex    string   `yaml:"splunk_index"`
	FailOn         string   `yaml:"fail_on"`
	Approved       []string `yaml:"approved"`
	Ignore         []string `yaml:"ignore"`
	Baseline       string   `yaml:"baseline"`
	BaselineKeyEnv string   `yaml:"baseline_key_env"`
	InputFormat    string   `yaml:"input_format"`
}

// Load reads a config file from the given path and validates its contents.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return &cfg, nil
}

// LoadDefault reads an explicit policy path, or ./mcpsec.yaml when that file exists.
func LoadDefault(explicit string) (*Config, error) {
	if explicit != "" {
		return Load(explicit)
	}
	const conventional = "mcpsec.yaml"
	if _, err := os.Stat(conventional); err == nil {
		return Load(conventional)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return &Config{}, nil
}

func (c *Config) validate() error {
	if c.SplunkURL != "" {
		parsed, err := url.Parse(c.SplunkURL)
		if err != nil {
			return fmt.Errorf("invalid splunk_url: %w", err)
		}
		if parsed.Scheme != "https" {
			return fmt.Errorf("splunk_url must use HTTPS (got %q)", parsed.Scheme)
		}
	}

	validFormats := map[string]bool{"": true, "table": true, "json": true, "sarif": true, "splunk": true}
	if !validFormats[strings.ToLower(c.Format)] {
		return fmt.Errorf("invalid format %q: must be table, json, sarif, or splunk", c.Format)
	}
	validInputs := map[string]bool{"": true, "auto": true, "mcpservers": true, "dxt": true, "dxtdir": true}
	if !validInputs[strings.ToLower(c.InputFormat)] {
		return fmt.Errorf("invalid input_format %q", c.InputFormat)
	}
	for _, id := range c.Ignore {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("ignore contains an empty rule ID")
		}
	}

	validSevs := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, sev := range c.Severity {
		if !validSevs[strings.ToLower(sev)] {
			return fmt.Errorf("invalid severity %q: must be critical, high, medium, low, or info", sev)
		}
	}

	if c.FailOn != "" && !validSevs[strings.ToLower(c.FailOn)] {
		return fmt.Errorf("invalid fail_on %q: must be critical, high, medium, low, or info", c.FailOn)
	}

	return nil
}
