package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the mcpsec configuration.
type Config struct {
	RulesDir    string   `yaml:"rules_dir"`
	Format      string   `yaml:"format"`
	Output      string   `yaml:"output"`
	Severity    []string `yaml:"severity"`
	SplunkURL   string   `yaml:"splunk_url"`
	SplunkToken string   `yaml:"splunk_token"`
	SplunkIndex string   `yaml:"splunk_index"`
	FailOn      string   `yaml:"fail_on"`
}

// Load reads a config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
