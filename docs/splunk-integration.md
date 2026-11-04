# Splunk Integration Guide

MCPSec can send scan results directly to Splunk via HTTP Event Collector (HEC) and includes a bundled Splunk app with a pre-built MCP Security Posture dashboard.

## Prerequisites

- Splunk Enterprise or Splunk Cloud instance
- Admin access to configure HEC
- MCPSec installed

## Setting Up Splunk HEC

### 1. Create an HEC Token

1. In Splunk Web, navigate to **Settings > Data Inputs > HTTP Event Collector**.
2. Click **New Token**.
3. Set the name to `mcpsec`.
4. On the Input Settings page:
   - **Source type**: `mcpsec:finding`
   - **Index**: Create or select an index (e.g., `mcpsec`)
5. Click **Review** and then **Submit**.
6. Copy the generated token.

### 2. Enable HEC

1. Go to **Settings > Data Inputs > HTTP Event Collector**.
2. Click **Global Settings**.
3. Set **All Tokens** to **Enabled**.
4. Note the HTTP port (default: 8088).

### 3. Create the mcpsec Index

1. Navigate to **Settings > Indexes**.
2. Click **New Index**.
3. Set the index name to `mcpsec`.
4. Configure retention as appropriate for your environment.
5. Click **Save**.

## Sending Results to Splunk

### Direct HEC Output

```bash
export MCPSEC_SPLUNK_TOKEN="your-hec-token"

mcpsec scan --format splunk \
  --splunk-url https://your-splunk:8088 \
  --splunk-index mcpsec \
  mcp-config.json
```

Prefer `MCPSEC_SPLUNK_TOKEN` because command-line token values can be exposed through process listings. The `--splunk-token` flag remains available for compatibility and emits a warning.

### Using Environment Variables

```bash
export MCPSEC_SPLUNK_TOKEN="your-hec-token"

mcpsec scan --format splunk \
  --splunk-url https://your-splunk:8088 \
  --splunk-index mcpsec \
  mcp-config.json
```

### File Output (Splunk HEC format)

If no `--splunk-url` is provided, HEC-formatted events are written to stdout or the output file:

```bash
mcpsec scan --format splunk -o events.json mcp-config.json
```

Each event is a self-contained Splunk HEC JSON object. The OCSF payload is nested in `event`, and HEC indexes that object as `_raw`. Findings include `unmapped.owasp_mcp` so searches can group by OWASP MCP Top 10:2025 beta category without parsing rule IDs. The HEC sourcetype is `mcpsec:finding`.

## Installing the Splunk App

A pre-built Splunk app is included in `splunk/app/`.

1. Package the app:
   ```bash
   tar -czf mcpsec-app.tar.gz -C splunk/app .
   ```
2. In Splunk Web, go to **Apps > Manage Apps > Install App from File**.
3. Upload `mcpsec-app.tar.gz`.
4. Restart Splunk if prompted.

## Dashboard

Import the MCP Security Posture dashboard:

1. Navigate to **Dashboards > Create New Dashboard**.
2. Select **Source** (XML editor).
3. Paste the contents of `splunk/dashboards/mcp_security_posture.xml`.
4. Save.

The dashboard queries `index=mcpsec sourcetype=mcpsec:finding` and reads the OCSF fields MCPSec emits (`finding.uid`, `resources{}.name`, `severity`, and `unmapped.owasp_mcp`). It provides:

- **Findings by Severity** -- Pie chart of critical/high/medium/low findings
- **Findings by OWASP Category** -- Bar chart of MCP01-MCP10 distribution, using the 2025 beta names
- **Top Affected Servers** -- Column chart of servers with most findings
- **Recent Findings** -- Table of latest findings with details

The Splunk app in `splunk/app/` also ships lookup tables for those category and severity names (`lookups/mcpsec_owasp_categories.csv` and `lookups/mcpsec_severity.csv`). Install the app before relying on the `category` and `severity_label` fields in ad hoc search. The pasted dashboard does not require the lookups.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused | Verify HEC is enabled and the port is correct |
| 403 Forbidden | Check that the HEC token is valid and enabled |
| Events not appearing | Verify the index exists and the token has access |
| TLS errors | Ensure the Splunk certificate is trusted, or use a valid cert |
