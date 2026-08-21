# Rules Authoring Guide

This guide explains how to write YAML-based security rules for MCPSec.

## Rule Structure

Each rule is a single YAML file in the `rules/` directory. Filenames follow the pattern `mcpXX-description.yaml`.

### Schema

```yaml
id: MCP04-R01
name: Plain-text API key in tool environment
severity: critical   # critical | high | medium | low | info
owasp_mcp: MCP04
description: |
  Multi-line description of what this rule detects and why it matters.
references:
  - https://owasp.org/www-project-mcp-top-10/
match:
  path: "$.mcpServers.*..env"          # Required for jsonpath/not_regex
  pattern: "(api[_-]?key|secret)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/]{20,}"
  type: jsonpath   # regex | jsonpath | not_regex
remediation: |
  Multi-line remediation guidance.
```

## Fields Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule ID. Format: `MCPxx-Rxx` (e.g., `MCP04-R01`) |
| `name` | Yes | Human-readable rule name |
| `severity` | Yes | One of: `critical`, `high`, `medium`, `low`, `info` |
| `owasp_mcp` | Yes | OWASP MCP Top 10 category (e.g., `MCP04`) |
| `description` | Yes | Detailed explanation of the security concern |
| `references` | No | List of URLs for further reading |
| `match` | Yes | Detection logic (see below) |
| `match.type` | Yes | Match type: `regex`, `jsonpath`, or `not_regex` |
| `scope` | No | `remote` to run only against network servers; omitted/`any` runs against all servers |
| `match.pattern` | Yes | Go-compatible regular expression |
| `match.path` | For `jsonpath`/`not_regex` | JSONPath to the server element being matched |
| `remediation` | Yes | Actionable fix guidance |

## Match Types

### Regex Match

Scans the JSON representation of each individual MCP server for patterns. This is the most common match type.

```yaml
match:
  type: regex
  pattern: "(api[_-]?key|secret|token|password)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/]{20,}"
```

The pattern is compiled as a Go regexp and matched against one server at a time. Use `(?i)` for case-insensitive matching. Go regular expressions do not support lookarounds; use `not_regex` for absence checks.

### JSONPath Match

Evaluates a JSONPath expression and applies the regex to each selected value:

```yaml
match:
  type: jsonpath
  path: "$.mcpServers[*].env[*]"
  pattern: "sk-[a-zA-Z0-9]{20,}"
```

Supported JSONPath features are object fields, `*`/`[*]` wildcards, and recursive descent such as `..env`. Paths beginning with `$.mcpServers.*` are evaluated relative to each server so findings are attributed correctly.

### Negative Regex Match

Use `not_regex` with a path to report a finding when a selected value does not contain the pattern:

```yaml
scope: remote
match:
  type: not_regex
  path: "$.mcpServers.*"
  pattern: "\"auth\"\\s*:"
```

The optional `scope: remote` limits a rule to servers with a URL or recognized network transport. Omit it, or use `scope: any`, for rules that apply to local and remote servers.

## Severity Guidelines

| Severity | When to use | Examples |
|----------|------------|---------|
| **critical** | Direct exploitation possible, immediate credential exposure | Hardcoded API keys, missing auth on public server |
| **high** | Significant security weakness | Wildcard permissions, HTTP transport, SSRF-prone URIs |
| **medium** | Security concern requiring attention | Missing schemas, no logging, no rate limiting |
| **low** | Hardening recommendation | Minor config improvements |
| **info** | Informational, no direct risk | Best practice suggestions |

## Testing Your Rule

1. Verify it matches `testdata/vulnerable-server.json`:
   ```bash
   mcpsec scan --rules ./rules/ testdata/vulnerable-server.json
   ```

2. Verify it does NOT match `testdata/safe-server.json`:
   ```bash
   mcpsec scan --rules ./rules/ testdata/safe-server.json
   ```

3. Validate the rule schema:
   ```bash
   mcpsec rules validate rules/your-rule.yaml
   ```

## Example: Complete Rule

```yaml
id: MCP07-R01
name: Insecure HTTP Transport
severity: high
owasp_mcp: MCP07
description: |
  MCP server URL uses plain HTTP instead of HTTPS, exposing all
  communication to eavesdropping and man-in-the-middle attacks.
references:
  - https://owasp.org/www-project-mcp-top-10/
match:
  path: "$.mcpServers[*].url"
  pattern: "^http://"
  type: jsonpath
remediation: |
  Change the server URL to use HTTPS. Configure TLS 1.2+ with
  strong cipher suites. Obtain a valid TLS certificate.
```

## Submitting a Rule

1. Use the [New Rule issue template](https://github.com/pfrederiksen/mcpsec/issues/new?template=new_rule.md) to propose your rule
2. Fork the repo and add your `.yaml` file to `rules/`
3. Run `mcpsec rules validate` and `go test ./...` to verify
4. Submit a PR referencing the issue

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contribution workflow.
