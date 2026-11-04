package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcpsec.yaml")
	body := []byte("fail_on: high\nformat: sarif\napproved:\n  - github\nignore:\n  - MCP07-001\nbaseline_key_env: BASELINE_KEY\n")
	require.NoError(t, os.WriteFile(path, body, 0o600))
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "high", cfg.FailOn)
	assert.Equal(t, "sarif", cfg.Format)
	assert.Equal(t, []string{"github"}, cfg.Approved)
	assert.Equal(t, []string{"MCP07-001"}, cfg.Ignore)
	assert.Equal(t, "BASELINE_KEY", cfg.BaselineKeyEnv)
}

func TestLoadRejectsBadFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcpsec.yaml")
	require.NoError(t, os.WriteFile(path, []byte("format: xml\n"), 0o600))
	_, err := Load(path)
	assert.ErrorContains(t, err, "format")
}
