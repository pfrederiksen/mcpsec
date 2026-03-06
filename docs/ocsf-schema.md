# OCSF Output Schema Reference

MCPSec outputs findings in the [Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io/) format, enabling integration with SIEMs, security data lakes, and SOAR platforms.

## Event Class

MCPSec uses OCSF **Security Finding** (class_uid: `2001`).

## Field Reference

### Top-Level Fields

| Field | Type | Description | Value |
|-------|------|-------------|-------|
| `class_uid` | integer | OCSF event class | `2001` (Security Finding) |
| `category_uid` | integer | Event category | `2` (Findings) |
| `activity_id` | integer | Activity type | `1` (Create) |
| `severity_id` | integer | Severity level (1-5) | See mapping below |
| `severity` | string | Severity label | `critical`, `high`, `medium`, `low`, `info` |
| `time` | long | Unix timestamp of the finding | e.g., `1772757930` |

### Severity Mapping

| severity_id | Label | Description |
|-------------|-------|-------------|
| 1 | Info | Informational, no direct risk |
| 2 | Low | Minor hardening recommendation |
| 3 | Medium | Security concern requiring attention |
| 4 | High | Significant security weakness |
| 5 | Critical | Direct exploitation possible |

### `finding` Object

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `finding.uid` | string | Rule identifier | `"MCP04-001"` |
| `finding.title` | string | Finding title | `"Plain-text secret in server environment"` |
| `finding.desc` | string | Detailed description | `"Server environment variable contains..."` |
| `finding.remediation.desc` | string | Remediation guidance | `"Move secrets to a secrets manager..."` |

### `resources` Array

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `resources[].type` | string | Resource type | `"MCP Server"` |
| `resources[].name` | string | Resource identifier | `"mcpserver:vulnerable-demo"` |

### `metadata` Object

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `metadata.product.name` | string | Scanner name | `"MCPSec Audit"` |
| `metadata.version` | string | Scanner version | `"1.0.0"` |

## Complete Example

```json
{
  "class_uid": 2001,
  "category_uid": 2,
  "activity_id": 1,
  "severity_id": 5,
  "severity": "critical",
  "time": 1772757930,
  "finding": {
    "uid": "MCP04-001",
    "title": "Plain-text secret in server environment",
    "desc": "Server environment variable contains a plain-text secret or API key, exposing credentials to any process reading the config.",
    "remediation": {
      "desc": "Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault) and inject at runtime via environment variable references, not literals."
    }
  },
  "resources": [
    {
      "type": "MCP Server",
      "name": "mcpserver:github"
    }
  ],
  "metadata": {
    "product": {
      "name": "MCPSec Audit"
    },
    "version": "1.0.0"
  }
}
```

## Usage

```bash
# Output findings as OCSF JSON to stdout
mcpsec scan --format json mcp-config.json

# Output OCSF JSON to a file
mcpsec scan --format json -o findings.json mcp-config.json

# Pipe to jq for filtering
mcpsec scan --format json mcp-config.json | jq '.[] | select(.severity == "critical")'
```
