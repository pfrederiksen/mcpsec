# MCPSec Improvement Plan

This plan records the gaps that remain after the OWASP MCP Top 10:2025 beta alignment. Built-in checks, YAML rules, OCSF output, and the Splunk dashboard now share one category vocabulary. The items below are the next product changes, in the order they remove the most user-facing inconsistency.

## Next

### Shared output flags for every scan command

`scan` writes a table, OCSF JSON, or Splunk HEC, and it can fail a job with `--fail-on`. `active` and `source` always write a table. `discover` writes inventory JSON, or a table when `--approved` is set. A CI job that inventories clients or reviews server source cannot reuse the GitHub Action's summary file or the OCSF pipeline.

Give `active`, `source`, and the shadow-finding mode of `discover` the same `--format`, `--output`, `--severity`, `--fail-on`, and `--summary-output` flags that `scan` already has. Keep `discover` without `--approved` as inventory JSON, since that result is not a finding list.

### SARIF for GitHub code scanning

OCSF is the SIEM shape. Pull requests need SARIF so GitHub can show findings on the changed config or source file. Add `--format sarif` for `scan` and `source`, with `ruleId`, the OWASP category, and a location that points at the config path or source line the lexical check already knows.

### Embed the default YAML rules

`brew install` and the GitHub Action ship the binary only. The `rules/` directory runs solely when someone passes `--rules`, so the documented community rules are absent from the default scan. Embed `rules/` with `go:embed` and load them unless `--rules` points somewhere else. `--rules` should replace the embedded set, not silently merge with it, until finding deduplication exists.

The embedded set still has no file for MCP04 (supply chain) or MCP09 (shadow servers). Those categories are covered by `SupplyChainCheck` and `discover --approved`. Add YAML rules only where they detect evidence the Go checks do not, so a default scan does not report the same proof twice.

### Read-only remote catalogs beyond tools

`active` sends `initialize`, `notifications/initialized`, and paginated `tools/list`. It does not call tools or read resources. Servers also advertise resources and prompts. Extend the same lifecycle with paginated `resources/list` and `prompts/list`, and run the existing description and schema checks on those definitions. Do not call `resources/read`, `prompts/get`, or any tool.

## Later

### Project and client discovery

`discover` knows per-user Claude Desktop, Cursor, VS Code, Windsurf, and Copilot paths, plus `.vscode/mcp.json` and `.mcp.json` in the working directory. It does not yet look for `.cursor/mcp.json` inside a repo, Claude project settings, Zed, or Gemini CLI configs. Add those paths, and print the client name the path implies, which `inferClients` already starts to do.

### Organization policy file

Approved server names, fail-on severity, ignored rule IDs, and the rules directory are flags. A committed `mcpsec.yaml` would let a repository state that policy once and have local runs and the GitHub Action read it. Flags should override the file.

### Signed baselines

`baseline create` writes SHA-256 fingerprints and deliberately omits secret values. Anyone who can edit the baseline file can approve their own drift. Sign the baseline with a key the CI job already has, and make `scan --baseline` reject a file whose signature does not verify.

### One finding per piece of evidence

Built-in checks and YAML rules share a pipeline and can both match the same server field. After the default rules are embedded, deduplicate on rule category, resource, and matched field, and keep the more specific rule ID. Per-tool findings are already collapsed to a count. This is the same idea applied across engines.

### OCSF schema check in CI

Events use Security Finding (`class_uid` 2001) plus `unmapped.owasp_mcp`. CI should validate a fixture scan against the OCSF schema so a later field rename cannot ship a dashboard that queries paths the scanner no longer writes. The Splunk dashboard and `docs/ocsf-schema.md` have to change in the same commit as the encoder.

### Tighten high-signal source and intent rules

`source` is lexical and tells reviewers the match is a candidate, not an exploit. Intent-flow rules match phrases such as "silently" and "must call this tool". Collect false-positive reports through the existing issue template and narrow those patterns with `testdata/safe-server.json` as the regression fixture. Do not add a finding for a missing server-side control just because the client config lacks a nonstandard field. That boundary is what keeps a clean config clean.
