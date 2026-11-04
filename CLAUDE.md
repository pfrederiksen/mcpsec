# MCPSec Audit -- Claude Code Project Context

## What This Is
MCPSec Audit is an open-source CLI security scanner for Model Context Protocol (MCP) configurations, remote tool inventories, and server source code. It is aligned to the OWASP MCP Top 10:2025 beta. Think Prowler, but for MCP.

## Tech Stack
- **Language:** Go 1.25+
- **CLI Framework:** Cobra (github.com/spf13/cobra)
- **Testing:** testify (github.com/stretchr/testify)
- **YAML Parsing:** gopkg.in/yaml.v3
- **Output Formats:** OCSF JSON (class_uid 2001, with `unmapped.owasp_mcp`), human-readable table, Splunk HEC (`sourcetype=mcpsec:finding`)

## Project Layout
```
cmd/mcpsec/main.go            -- CLI entrypoint (scan, baseline, discover, active, source, rules, version)
internal/scanner/             -- Scan orchestration, config parsing, baseline, discovery, active, and source modes
internal/checks/              -- Built-in checks. One OWASP risk may span more than one file
internal/rules/               -- Strict YAML loader + per-server regex/JSONPath/not-regex engine
internal/output/              -- OCSF, table, and Splunk HEC formatters
internal/config/              -- Config file parsing
rules/                        -- YAML rules. The filename prefix matches owasp_mcp
testdata/                     -- Fixtures: vulnerable-server.json, safe-server.json, dxt-manifest.json
splunk/                       -- Splunk app, lookups, and MCP Security Posture dashboard
docs/                         -- rules-authoring.md, ocsf-schema.md, splunk-integration.md, roadmap.md
```

## Key Patterns
- Built-in checks implement `Check`: `Run(ctx CheckContext) []CheckFinding`
- YAML rules are an optional second layer via `--rules`. They are not embedded in the binary
- Both engines produce findings through the same output pipeline
- Findings map to OCSF Security Finding (class_uid 2001). The OWASP category is `unmapped.owasp_mcp`
- Per-tool findings (duplicate tools, missing schemas) are deduplicated into one finding with a count
- The supplemental rate-limit check is not registered. Its IDs are `SUP-001` and `SUP-002`, not MCP10
- `scan`, `discover`, `baseline`, and `source` never execute a configured MCP server. `active` sends only initialize and paginated `tools/list`

## Supported Input Formats
- **mcpServers JSON** -- `{"mcpServers": {...}}` (Claude Desktop, Cursor, Windsurf) and VS Code `{"servers": {...}}`
- **DXT manifest** -- Claude Desktop Extension `manifest.json` with `dxt_version`
- **DXT directory** -- Directory containing extension subdirs with `manifest.json` files
- Auto-detection probes for a non-empty `mcpServers` or `servers` object, then `dxt_version`, then directory structure. Empty and unsupported inputs fail closed

## Commands
```bash
go build ./...                           # Build
go test ./... -race                      # Run all tests with the race detector
go test ./... -race -coverprofile=c.out  # Tests with coverage
golangci-lint run                        # Lint
make build / make test / make lint       # Makefile shortcuts
mcpsec scan <file-or-dir>                # Scan a config
mcpsec scan --format json <file>         # OCSF JSON output
mcpsec scan --severity critical <file>   # Filter by severity
mcpsec scan --input-format dxt <file>    # Force input format
mcpsec baseline create <file> -o out.json
mcpsec discover [--approved name1,name2]
mcpsec active <MCP-URL>                  # Read-only remote tool inventory
mcpsec source <directory>                # Lexical source review
mcpsec rules list                        # List YAML rules
mcpsec rules validate <rule.yaml>        # Validate a rule file
```

## Testing Conventions
- Table-driven tests with testify assertions
- testdata/vulnerable-server.json must trigger MCP01–MCP08 and MCP10. MCP09 comes from `discover --approved`, not from a single config file
- testdata/safe-server.json must trigger zero findings
- testdata/dxt-manifest.json tests DXT format auto-detection
- All tests must pass with `-race` flag

## OWASP MCP Top 10:2025 Beta Mapping
| Check file | OWASP | Description |
|---|---|---|
| secrets.go | MCP01 | Token Mismanagement & Secret Exposure |
| permissions.go | MCP02 | Privilege Escalation via Scope Creep |
| prompt_injection.go, tool_spoofing.go, schema.go | MCP03 | Tool Poisoning |
| supply_chain.go | MCP04 | Software Supply Chain Attacks & Dependency Tampering |
| startup_command.go, unsafe_resource.go | MCP05 | Command Injection & Execution |
| intent_flow.go | MCP06 | Intent Flow Subversion |
| auth.go, transport.go | MCP07 | Insufficient Authentication & Authorization |
| audit_logging.go | MCP08 | Lack of Audit and Telemetry |
| scanner/discovery.go (`discover --approved`) | MCP09 | Shadow MCP Servers |
| context_exposure.go | MCP10 | Context Injection & Over-Sharing |
| resource_exhaustion.go | supplemental | Unregistered rate-limit check (`SUP-` IDs) |

## GitHub
- Repo: github.com/pfrederiksen/mcpsec
- CI: go vet + staticcheck + golangci-lint + go test -race
- Releases: GoReleaser on tag push (v*)

## Style Preferences
- Keep checks focused. A new OWASP risk gets its own file; extra evidence for an existing risk can too
- Prefer table-driven tests
- Use OCSF field names in output structs
- Rule IDs follow pattern: MCPxx-xxx (e.g., MCP01-101). Supplemental checks use SUP-xxx
- YAML rule IDs follow pattern: MCPxx-Rxx (e.g., MCP01-R01)
- YAML filenames follow pattern: mcpXX-description.yaml, and XX matches owasp_mcp
- Per-tool findings are deduplicated (one finding with count, not N separate findings)
- Never commit secrets or test fixtures containing real credentials
