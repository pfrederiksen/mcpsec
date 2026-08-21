![MCPSec Audit banner](docs/assets/mcpsec-banner.png)

[![CI](https://github.com/pfrederiksen/mcpsec/actions/workflows/ci.yml/badge.svg)](https://github.com/pfrederiksen/mcpsec/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# MCPSec Audit

Security scanner for Model Context Protocol (MCP) configurations, remote servers, and server source code. Think [Prowler](https://github.com/prowler-cloud/prowler), but purpose-built for MCP and aligned to the [OWASP MCP Top 10:2025 beta](https://owasp.org/www-project-mcp-top-10/).

MCPSec performs evidence-based static config checks, approved-baseline drift detection, multi-client inventory and shadow-server policy checks, read-only remote MCP enumeration, and conservative lexical source analysis. It outputs findings in OCSF JSON or human-readable tables and supports a pluggable YAML rules engine.

MCPSec never executes a configured MCP server during `scan`, `discover`, `baseline`, or `source`. The opt-in `active` command sends only MCP initialization lifecycle messages and paginated tool-inventory requests; it never invokes tools or reads resources.

---

## Use Cases

- **Developer laptop audit** -- Find hardcoded secrets, dangerous startup commands, mutable packages, excessive declared permissions, and broad filesystem exposure
- **MCP inventory** -- Discover Claude Desktop, Cursor, VS Code, and Windsurf configurations and compare server names with an approved inventory
- **CI/CD gate** -- Add `mcpsec scan --fail-on high` to your pipeline to block deploys with critical or high-severity MCP misconfigurations
- **Change control** -- Baseline approved server definitions and detect command, argument, environment, endpoint, or tool-definition drift
- **Remote assessment** -- Enumerate a server's advertised tools without invoking them and inspect descriptions and input schemas
- **Server code review** -- Locate high-signal command injection, path traversal, SSRF, token-passthrough, and authorization patterns for manual confirmation
- **Claude Desktop Extension (DXT) review** -- Audit DXT manifests or an Extensions directory for secrets and unsafe tool definitions
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

### GitHub Action

```yaml
- uses: pfrederiksen/mcpsec@v1
  with:
    config: path/to/mcp-config.json
    fail-on: high
```

See [GitHub Action usage](#github-action) below for full options.

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

# Approve a config, then detect later drift
mcpsec baseline create mcp-config.json --output mcpsec-baseline.json
mcpsec scan --baseline mcpsec-baseline.json mcp-config.json

# Inventory known client configs; optionally flag servers outside an allowlist
mcpsec discover
mcpsec discover --approved github,postgres

# Read-only remote enumeration (HTTPS and public addresses by default)
MCPSEC_ACTIVE_TOKEN='...' mcpsec active https://mcp.example.com/mcp

# Conservative lexical source scan; review results manually
mcpsec source ./server
```

---

## Example Output

### Table (default)

```
----------------------------------------------------------------------------------------------------
RULE ID      NAME                                          SEVERITY   RESOURCE
----------------------------------------------------------------------------------------------------
MCP03-101    Potential prompt injection in tool descrip... HIGH       mcpserver:vulnerable-demo
MCP02-002    Excessive tool permissions                    CRITICAL   mcpserver:vulnerable-demo
MCP01-101    Plain-text secret in server environment       CRITICAL   mcpserver:vulnerable-demo
MCP01-102    Plain-text secret in tool environment         CRITICAL   mcpserver:vulnerable-demo
MCP05-001    Dangerous URI scheme in tool configuration    HIGH       mcpserver:vulnerable-demo
MCP05-002    Tool URI targets internal network             HIGH       mcpserver:vulnerable-demo
MCP03-201    Duplicate tool name detected                  HIGH       mcpserver:vulnerable-demo
MCP06-101    Tool attempts to subvert user intent or ap... HIGH       mcpserver:vulnerable-demo
MCP07-001    Insecure HTTP transport                       HIGH       mcpserver:vulnerable-demo
MCP07-003    Weak TLS version configured                   HIGH       mcpserver:vulnerable-demo
MCP03-301    Missing input schema for tool                 MEDIUM     mcpserver:vulnerable-demo
MCP04-101    Unpinned package executed as MCP server       HIGH       mcpserver:mutable-local-server
MCP05-103    Download-and-execute startup chain            CRITICAL   mcpserver:shell-server
MCP10-101    Broad host context exposed to MCP server      HIGH       mcpserver:mutable-local-server
----------------------------------------------------------------------------------------------------
Total: 17 finding(s)
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
    "uid": "MCP03-101",
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
| Client JSON | `--input-format mcpservers` | `mcpServers` (Claude/Cursor/Windsurf) or `servers` (VS Code) envelope | `claude_desktop_config.json`, `mcp.json` |
| DXT manifest | `--input-format dxt` | Claude Desktop Extension manifest | `manifest.json` |
| DXT directory | `--input-format dxtdir` | Directory of DXT extensions | `Claude Extensions/` |
| Auto (default) | `--input-format auto` | Detects format from file content/structure | Any of the above |

Inputs must contain at least one MCP server. Duplicate JSON keys, unsupported formats, malformed DXT manifests, and files larger than 10 MiB are rejected rather than treated as clean scans. Directory scans fail if an extension manifest exists but cannot be read or parsed.

---

## OWASP MCP Top 10:2025 Beta Coverage

| OWASP | Beta risk | Implemented evidence |
|-------|-----------|----------------------|
| MCP01 | Token Mismanagement & Secret Exposure | Inline environment, tool, API-key, token, bearer-token, private-key, and credential patterns |
| MCP02 | Privilege Escalation via Scope Creep | Explicit wildcard, admin, root, filesystem, network, shell, and broad read/write grants |
| MCP03 | Tool Poisoning | Instruction-like descriptions, duplicate names, missing schemas, schema-validation opt-out, and baseline definition drift |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | Unpinned package runners, mutable container tags, unpinned Git references, and approved baselines |
| MCP05 | Command Injection & Execution | Shell launchers, privileged/destructive commands, download-and-execute chains, encoded payloads, sensitive paths, unsafe URIs, plus source patterns |
| MCP06 | Intent Flow Subversion | Tool metadata that suppresses confirmation, forces invocation, or attempts to bypass approval |
| MCP07 | Insufficient Authentication & Authorization | Explicitly incomplete auth, OAuth token passthrough, resource/audience binding, PKCE and redirect settings, insecure transport/TLS, unauthenticated active enumeration, and source token-passthrough patterns |
| MCP08 | Lack of Audit and Telemetry | Explicitly disabled logging/audit settings and remote inventory failures |
| MCP09 | Shadow MCP Servers | Multi-client discovery plus an explicit `--approved` server-name policy |
| MCP10 | Context Injection & Over-Sharing | Broad home, system, filesystem-root, mount, and read-scope arguments |

The scanner reports what its input can establish. Standard client configuration does not prove whether a remote implementation has server-side authorization, audit logging, rate limits, sandboxing, or secure business logic. MCPSec therefore does not report those controls as missing solely because nonstandard config fields are absent. Use `active`, `source`, and deployment-specific review to increase assurance.

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
      --summary-output string Write a JSON scan summary to this file
      --baseline string       Compare with an approved baseline
      --fail-on string        Exit with code 1 if findings at or above this severity
      --splunk-url string     Splunk HEC endpoint URL
      --splunk-token string   Splunk HEC token (also reads MCPSEC_SPLUNK_TOKEN env var)
      --splunk-index string   Splunk index name
  -q, --quiet                 Suppress output except findings
```

### `mcpsec baseline create [config-file] --output [file]`

Writes SHA-256 fingerprints of normalized server definitions. Later, `scan --baseline` reports added, removed, or modified servers. Baselines can contain hashes of secret-bearing definitions, but not the secret values themselves.

### `mcpsec discover [path...]`

Inventories MCP configs. With no paths, checks established per-user Claude Desktop, Cursor, VS Code, and Windsurf locations. Directory arguments are searched while `.git` and `node_modules` are skipped.

Use `--approved name1,name2` to report every other discovered server as OWASP MCP09 shadow MCP. Approval is an explicit policy; discovery alone does not assume that an installed server is unauthorized.

### `mcpsec active [MCP-URL]`

Sends `initialize`, `notifications/initialized`, and paginated `tools/list`, then applies tool-definition checks. It does not call tools, read resources, render prompts, request model sampling, or accept elicitation. HTTPS and public addresses are required by default; `--allow-private` explicitly permits private/local and HTTP development endpoints. Set a bearer token in `MCPSEC_ACTIVE_TOKEN`, or name another variable with `--token-env`; tokens are never accepted as command-line values.

### `mcpsec source [directory]`

Performs lexical checks over Go, Python, JavaScript, TypeScript, Java, and Rust source without building or running it. Source findings identify review candidates, not proven exploitability.

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

## GitHub Action

MCPSec is available as a GitHub Action on the [GitHub Marketplace](https://github.com/marketplace/actions/mcpsec-audit). Add it to any workflow to scan MCP configs on every push or pull request.

### Basic usage

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  mcpsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: pfrederiksen/mcpsec@v1
        with:
          config: mcp-config.json
          fail-on: high
```

### Full options

```yaml
- uses: pfrederiksen/mcpsec@v1
  with:
    # Required: path to MCP config file or directory
    config: path/to/mcp-config.json

    # Output format: table, json, splunk (default: table)
    format: json

    # Filter by severity (comma-separated)
    severity: critical,high

    # Fail the step if findings at or above this severity
    fail-on: high

    # Custom rules directory
    rules: ./my-rules/

    # Input format: auto, mcpservers, dxt, dxtdir (default: auto)
    input-format: auto

    # Save findings to a file
    output: findings.json

    # Compare with a committed approved baseline
    baseline: mcpsec-baseline.json

    # MCPSec version to install (default: latest)
    version: latest
```

### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings detected |
| `results-file` | Path to the output file (if `output` was set) |

### Example: upload findings as artifact

```yaml
jobs:
  mcpsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: pfrederiksen/mcpsec@v1
        id: scan
        with:
          config: mcp-config.json
          format: json
          output: mcpsec-findings.json
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: mcpsec-findings
          path: mcpsec-findings.json
```

### Example: scan DXT extensions in CI

```yaml
- uses: pfrederiksen/mcpsec@v1
  with:
    config: extensions/
    input-format: dxtdir
    fail-on: critical
```

---

## YAML Rules Engine

MCPSec includes a pluggable YAML rules engine for community-contributed detections. Rules are Sigma-style YAML files:

```yaml
id: MCP01-CUSTOM-001
name: Plain-text API key in tool environment
severity: critical
owasp_mcp: MCP01
description: |
  Tool definition includes a plain-text API key or secret in the environment
  variables block, exposing credentials to any process reading the config.
references:
  - https://owasp.org/www-project-mcp-top-10/
match:
  path: "$.mcpServers.*..env"
  pattern: "(api[_-]?key|secret|token|password)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/]{20,}"
  type: jsonpath
remediation: |
  Move secrets to a secrets manager and inject at runtime via
  environment variable references, not literals.
```

Rules live in the `rules/` directory. Load a rule directory explicitly with `--rules`; no recompilation is needed:

```bash
mcpsec scan --rules ./rules mcp-config.json
```

Rules are strictly validated when loaded. Unknown fields, duplicate IDs, invalid regexes, unsupported match types, multiple YAML documents, and rule files larger than 1 MiB are rejected.

See [docs/rules-authoring.md](docs/rules-authoring.md) for the full authoring guide.

---

## Splunk Integration

MCPSec includes a Splunk HEC output mode and a bundled Splunk app with a pre-built MCP Security Posture dashboard.

```bash
export MCPSEC_SPLUNK_TOKEN="your-hec-token"

mcpsec scan --format splunk \
  --splunk-url https://your-splunk:8088 \
  --splunk-index mcpsec \
  mcp-config.json
```

The Splunk app is in `splunk/app/` with dashboards in `splunk/dashboards/`. See [docs/splunk-integration.md](docs/splunk-integration.md) for setup instructions.

---

## Architecture

MCPSec uses several evidence sources that feed one finding pipeline:

1. **Go checks** (`internal/checks/`) -- Compiled checks that understand parsed MCP configuration structure.

2. **YAML rules** (`rules/`) -- Optional regex/JSONPath rules loaded with `--rules`. Rules execute against one parsed server at a time, preventing matches from being attributed to unrelated servers.

3. **Baseline and discovery** -- Normalized definition fingerprints and explicit approved-name policy.

4. **Active and source scans** -- Read-only protocol inventory and lexical source review. These are separate, opt-in commands.

All scan modes produce the same finding model; `scan` supports table, OCSF JSON, and Splunk output. The newer specialized commands currently emit table or inventory JSON as documented above.

```
                     +------------------+
  Config/DXT ------->|  Format Detector |
  Active/source ---->+--------+---------+
                              |
                     +--------v---------+
                     |  Scanner Engine   |
                     +--------+---------+
                              |
              +---------------+---------------+
              |                               |
     +--------v---------+           +--------v---------+
     | Built-in Checks  |           |  YAML Rule Engine |
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
