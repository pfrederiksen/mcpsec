# MCPSec roadmap

The improvement plan that followed the OWASP MCP Top 10:2025 beta alignment is implemented. This page records what that means in the product, and the limits that are still intentional.

## In the product

- `scan`, `active`, `source`, and `discover --approved` share `--format` (`table`, `json`, `sarif`, `splunk`), `--output`, `--severity`, `--fail-on`, `--ignore`, and `--summary-output`.
- SARIF 2.1.0 carries the rule ID, the OWASP category, and a config path or source line.
- The YAML rules in `rules/` are compiled into the binary. `--rules` replaces them.
- `active` pages `tools/list`, `resources/list`, and `prompts/list`. It does not call tools, read resource bodies, or render prompts. A missing optional catalog method is not a finding.
- Discovery includes project `.cursor/mcp.json`, `.claude/mcp.json`, `.gemini/settings.json`, and `.zed/settings.json`, plus the per-user Gemini CLI and Zed locations.
- `./mcpsec.yaml` sets fail-on, format, approved names, ignored rule IDs, the baseline path, and the baseline key environment variable. Flags override the file. `mcpsec.yaml.example` shows the shape.
- `MCPSEC_BASELINE_KEY` HMAC-signs a baseline. A signed file is rejected when the key is missing or wrong. An unsigned file is rejected when a key is set.
- A YAML rule is dropped when a built-in check already covers the same category, server, and field. The built-in rule ID is the one that remains.
- CI runs `TestOCSFEventsMatchDashboardContract`, which fails if a Splunk dashboard `spath` no longer exists on an OCSF event. Events include `type_uid` 200101 and `unmapped.owasp_mcp`.

## Limits that stay

- `source` is a lexical review. A match is a candidate, not a proven exploit. Comments and fixed-argument calls are not reported.
- Intent-flow detection looks for approval-bypass phrases such as "must call this tool" and "without confirmation". A description that only says an operation "fails silently" is not a finding.
- A client config that omits a nonstandard field is not evidence that a remote server lacks authorization, audit logging, rate limits, or a sandbox. `active`, `source`, and deployment review are how that assurance increases.
- Baseline signatures are HMAC with a CI-held key. They detect an unapproved edit by someone who does not have the key. They are not a public-key signature.
- MCP04 and MCP09 remain built-in checks. The YAML set does not add a second copy of that evidence.
