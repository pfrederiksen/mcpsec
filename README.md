[![CI](https://github.com/pfrederiksen/mcpsec/actions/workflows/ci.yml/badge.svg)](https://github.com/pfrederiksen/mcpsec/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/pfrederiksen/mcpsec)](https://goreportcard.com/report/github.com/pfrederiksen/mcpsec)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# MCPSec Audit

OWASP MCP Top 10 security scanner for Model Context Protocol (MCP) server configurations. Think [Prowler](https://github.com/prowler-cloud/prowler), but purpose-built for MCP.

MCPSec audits MCP server definition files for security risks, outputs findings in OCSF JSON or human-readable tables, and supports a pluggable YAML rules engine for community-contributed detections.

---

## Use Cases

- **Developer laptop audit** -- Scan your Claude Desktop, Cursor, or VS Code MCP configs to find hardcoded API keys, missing auth, and overly broad permissions before they leak
- **CI/CD gate** -- Add `mcpsec scan --fail-on high` to your pipeline to block deploys with critical or high-severity MCP misconfigurations
- **Security team posture assessment** -- Scan all MCP configs across your org, output OCSF JSON to your SIEM, and track risk posture over time
- **Claude Desktop Extension (DXT) review** -- Audit DXT manifests or your entire Extensions directory for tool spoofing, missing schemas, and integrity violations
- **Compliance evidence** -- Generate machine-readable OCSF findings as audit artifacts for security reviews

---

## Quick Install

### Homebrew (macOS / Linux)

```bash
brew install pfrederiksen/tap/mcpsec
```

### Go Install

```bash
go install github.com/pfrederiksen/mcpsec@latest
```

### Download Binary

Download pre-built binaries from the [Releases page](https://github.com/pfrederiksen/mcpsec/releases) for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64).

### Build from Source

```bash
git clone https://github.com/pfrederiksen/mcpsec.git
cd mcpsec
make build
```

---

## Quick Start

```bash
# Scan an MCP server config file
mcpsec scan mcp-config.json

# Scan your Claude Desktop config
mcpsec scan ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Scan your Claude Desktop Extensions directory (auto-detected)
mcpsec scan ~/Library/Application\ Support/Claude/Claude\ Extensions/

# Scan a single DXT extension manifest
mcpsec scan ~/Library/Application\ Support/Claude/Claude\ Extensions/my-ext/manifest.json

# Output as OCSF JSON
mcpsec scan --format json mcp-config.json

# Only show critical and high findings
mcpsec scan --severity critical,high mcp-config.json

# Fail CI if critical findings exist
mcpsec scan --fail-on critical mcp-config.json
```

---

## Example Output

### Table (default)

```
----------------------------------------------------------------------------------------------------
RULE ID      NAME                                          SEVERITY   RESOURCE
----------------------------------------------------------------------------------------------------
MCP01-001    Potential prompt injection in tool descrip... HIGH       mcpserver:vulnerable-demo
MCP02-002    Excessive tool permissions                    CRITICAL   mcpserver:vulnerable-demo
MCP03-001    Missing authentication configuration          CRITICAL   mcpserver:vulnerable-demo
MCP04-001    Plain-text secret in server environment       CRITICAL   mcpserver:vulnerable-demo
MCP04-002    Plain-text secret in tool environment         CRITICAL   mcpserver:vulnerable-demo
MCP05-001    Dangerous URI scheme in tool configuration    HIGH       mcpserver:vulnerable-demo
MCP05-002    Tool URI targets internal network             HIGH       mcpserver:vulnerable-demo
MCP06-001    Duplicate tool name detected                  HIGH       mcpserver:vulnerable-demo
MCP06-002    Missing tool integrity hash                   MEDIUM     mcpserver:vulnerable-demo
MCP07-001    Insecure HTTP transport                       HIGH       mcpserver:vulnerable-demo
MCP07-003    Weak TLS version configured                   HIGH       mcpserver:vulnerable-demo
MCP08-001    Missing input schema for tool                 MEDIUM     mcpserver:vulnerable-demo
MCP08-002    Input schema validation not enabled           MEDIUM     mcpserver:vulnerable-demo
MCP09-001    No logging configuration                      MEDIUM     mcpserver:vulnerable-demo
MCP10-001    No rate limiting configured                   MEDIUM     mcpserver:vulnerable-demo
----------------------------------------------------------------------------------------------------
Total: 15 finding(s)
```

### OCSF JSON (`--format json`)

Each finding maps to an OCSF Security Finding (class_uid 2001):

```json
{
  "class_uid": 2001,
  "category_uid": 2,
  "activity_id": 1,
  "severity_id": 4,
  "severity": "high",
  "time": 1772757930,
  "finding": {
    "uid": "MCP01-001",
    "title": "Potential prompt injection in tool description",
    "desc": "Tool description contains instruction-like language that could be used to manipulate an LLM consuming tool output.",
    "remediation": {
      "desc": "Sanitize tool descriptions to remove instruction-like language."
    }
  },
  "resources": [
    {
      "type": "MCP Server",
      "name": "mcpserver:vulnerable-demo"
    }
  ],
  "metadata": {
    "product": {
      "name": "MCPSec Audit"
    },
    "version": "dev"
  }
}
```

---

## Supported Input Formats

MCPSec auto-detects config formats. You can also specify explicitly with `--input-format`:

| Format | Flag | Description | Example |
|--------|------|-------------|---------|
| `mcpServers` JSON | `--input-format mcpservers` | Standard MCP config (Claude Desktop, Cursor) | `claude_desktop_config.json` |
| DXT manifest | `--input-format dxt` | Claude Desktop Extension manifest | `manifest.json` |
| DXT directory | `--input-format dxtdir` | Directory of DXT extensions | `Claude Extensions/` |
| Auto (default) | `--input-format auto` | Detects format from file content/structure | Any of the above |

---

## OWASP MCP Top 10 Coverage

All 10 categories are implemented with built-in Go checks and YAML rules:

| OWASP | Risk | Rule IDs | Severity | Description |
|-------|------|----------|----------|-------------|
| MCP01 | Prompt Injection via Tool Output | MCP01-001 | High | Detects instruction-like patterns in tool descriptions |
| MCP02 | Excessive Tool Permissions | MCP02-001..003 | Critical/High | Flags wildcard perms, overprivileged tools, missing boundaries |
| MCP03 | Missing Authentication | MCP03-001..002 | Critical/High | Detects missing or incomplete auth configuration |
| MCP04 | Sensitive Data Exposure | MCP04-001..004 | Critical | Finds hardcoded API keys, tokens, passwords in env vars |
| MCP05 | Unsafe Resource Access | MCP05-001..002 | High | Detects SSRF-prone URIs (file://, internal IPs, metadata endpoints) |
| MCP06 | Tool Definition Spoofing | MCP06-001..002 | High/Medium | Flags duplicate tool names, missing integrity hashes |
| MCP07 | Insecure Transport | MCP07-001..003 | Critical/High | Detects HTTP URLs, disabled TLS, weak TLS versions |
| MCP08 | Unvalidated Tool Input Schemas | MCP08-001..002 | Medium | Flags tools without input schemas, disabled validation |
| MCP09 | Logging and Audit Deficiencies | MCP09-001..003 | Medium/High | Detects missing or disabled logging and audit trails |
| MCP10 | Denial of Service | MCP10-001..002 | Medium | Flags missing rate limiting and payload size limits |

---

## CLI Reference

### `mcpsec scan [config-file]`

Primary scan command. Accepts a config file path or directory.

```
Flags:
  -f, --format string         Output format: table, json, splunk (default "table")
  -o, --output string         Output file path (default: stdout)
      --rules string          Custom rules directory
      --severity string       Filter by severity (comma-separated: critical,high,medium,low,info)
      --input-format string   Input format: auto, mcpservers, dxt, dxtdir (default "auto")
      --fail-on string        Exit with code 1 if findings at or above this severity
      --splunk-url string     Splunk HEC endpoint URL
      --splunk-token string   Splunk HEC token (also reads MCPSEC_SPLUNK_TOKEN env var)
      --splunk-index string   Splunk index name
  -q, --quiet                 Suppress output except findings
```

### `mcpsec rules list`

List all loaded YAML rules with descriptions and severity.

### `mcpsec rules validate [rule.yaml]`

Validate a community-contributed rule file against the rule schema.

### `mcpsec version`

Print version and build info.

---

## Examples

### Scan Claude Desktop config

```bash
mcpsec scan ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Scan all Claude Desktop Extensions at once

```bash
mcpsec scan ~/Library/Application\ Support/Claude/Claude\ Extensions/
```

### Scan a single DXT extension

```bash
mcpsec scan path/to/extension/manifest.json
```

### Filter to critical findings only

```bash
mcpsec scan --severity critical mcp-config.json
```

### Output OCSF JSON to a file

```bash
mcpsec scan --format json -o findings.json mcp-config.json
```

### Fail CI on high-severity findings

```bash
mcpsec scan --fail-on high mcp-config.json || exit 1
```

### Use custom rules directory

```bash
mcpsec scan --rules ./my-rules/ mcp-config.json
```

### Send results to Splunk HEC

```bash
export MCPSEC_SPLUNK_TOKEN="your-hec-token"
mcpsec scan --format splunk --splunk-url https://splunk:8088 mcp-config.json
```

### List all available rules

```bash
mcpsec rules list
```

### Validate a community rule

```bash
mcpsec rules validate rules/mcp04-secret-exposure.yaml
```

---

## YAML Rules Engine

MCPSec includes a pluggable YAML rules engine for community-contributed detections. Rules are Sigma-style YAML files:

```yaml
id: MCP04-001
name: Plain-text API key in tool environment
severity: critical
owasp_mcp: MCP04
description: |
  Tool definition includes a plain-text API key or secret in the environment
  variables block, exposing credentials to any process reading the config.
references:
  - https://owasp.org/www-project-mcp-top-10/
match:
  path: "$.tools[*].environment[*]"
  pattern: "(api[_-]?key|secret|token|password)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/]{20,}"
  type: regex
remediation: |
  Move secrets to a secrets manager and inject at runtime via
  environment variable references, not literals.
```

Rules live in the `rules/` directory and are automatically loaded. Drop a new `.yaml` file in and it takes effect immediately -- no recompilation needed.

See [docs/rules-authoring.md](docs/rules-authoring.md) for the full authoring guide.

---

## Splunk Integration

MCPSec includes a Splunk HEC output mode and a bundled Splunk app with a pre-built MCP Security Posture dashboard.

```bash
mcpsec scan --format splunk \
  --splunk-url https://your-splunk:8088 \
  --splunk-token "$MCPSEC_SPLUNK_TOKEN" \
  --splunk-index mcpsec \
  mcp-config.json
```

The Splunk app is in `splunk/app/` with dashboards in `splunk/dashboards/`. See [docs/splunk-integration.md](docs/splunk-integration.md) for setup instructions.

---

## Architecture

MCPSec uses a dual-layer detection engine:

1. **Go checks** (`internal/checks/`) -- Compiled, type-safe checks that understand MCP server config structure. These perform semantic analysis (duplicate tool names, TLS version validation, credential pattern matching).

2. **YAML rules** (`rules/`) -- Regex/JSONPath-based rules that scan raw config text. Community-contributable without Go knowledge, following the Sigma model used in SIEM detections.

Both layers feed into the same Finding -> OCSF output pipeline.

```
                     +------------------+
  Config file ------>|  Format Detector |
  (mcpServers/DXT)   +--------+---------+
                              |
                     +--------v---------+
                     |  Scanner Engine   |
                     +--------+---------+
                              |
              +---------------+---------------+
              |                               |
     +--------v---------+           +--------v---------+
     |  Go Checks (10)  |           |  YAML Rule Engine |
     |  internal/checks/ |           |  rules/*.yaml     |
     +--------+---------+           +--------+---------+
              |                               |
              +---------------+---------------+
                              |
                     +--------v---------+
                     | Output Formatter  |
                     | (Table/OCSF/HEC)  |
                     +------------------+
```

---

## Contributing

We welcome contributions -- especially new YAML rules. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

- **New rules**: Use the [New Rule issue template](https://github.com/pfrederiksen/mcpsec/issues/new?template=new_rule.md) to propose, then submit a PR with a YAML file
- **Bug reports**: Use the [Bug Report template](https://github.com/pfrederiksen/mcpsec/issues/new?template=bug_report.md)
- **False positives**: Use the [False Positive template](https://github.com/pfrederiksen/mcpsec/issues/new?template=false_positive.md)

---

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.
