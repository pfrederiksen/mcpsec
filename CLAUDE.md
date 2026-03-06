# MCPSec Audit -- Claude Code Project Context

## What This Is
MCPSec Audit is an open-source CLI security scanner that implements the OWASP MCP Top 10 as automated checks against Model Context Protocol (MCP) server configurations. Think Prowler, but for MCP.

## Tech Stack
- **Language:** Go 1.26+
- **CLI Framework:** Cobra (github.com/spf13/cobra)
- **Testing:** testify (github.com/stretchr/testify)
- **YAML Parsing:** gopkg.in/yaml.v3
- **Output Formats:** OCSF JSON (class_uid 2001), human-readable table, Splunk HEC

## Project Layout
```
cmd/mcpsec/main.go           -- CLI entrypoint (cobra commands: scan, rules, version)
internal/scanner/             -- Core scan orchestration, config parsing, format auto-detection
internal/checks/              -- 10 check implementations (one per OWASP MCP risk)
internal/rules/               -- YAML rule loader + regex/jsonpath evaluation engine
internal/output/              -- OCSF, table, and Splunk HEC formatters
internal/config/              -- Config file parsing
rules/                        -- YAML rule definitions (Sigma-style, 10 files)
testdata/                     -- Fixtures: vulnerable-server.json, safe-server.json, dxt-manifest.json
splunk/                       -- Splunk app + MCP Security Posture dashboard
docs/                         -- rules-authoring.md, ocsf-schema.md, splunk-integration.md
```

## Key Patterns
- Each OWASP MCP risk (MCP01-MCP10) maps to a Go check in `internal/checks/` implementing the `Check` interface
- The `Check` interface: `Run(ctx CheckContext) []CheckFinding`
- YAML rules in `rules/` provide a second layer of detection via regex/jsonpath matching
- Both built-in checks and YAML rules produce findings through the same output pipeline
- Findings map to OCSF Security Finding (class_uid 2001) events
- Per-tool findings (MCP06 hash, MCP08 schema) are deduplicated into single findings with counts

## Supported Input Formats
- **mcpServers JSON** -- Standard `{"mcpServers": {...}}` format (Claude Desktop, Cursor)
- **DXT manifest** -- Claude Desktop Extension `manifest.json` with `dxt_version` field
- **DXT directory** -- Directory containing extension subdirs with `manifest.json` files
- Auto-detection probes for `mcpServers` key, then `dxt_version`, then directory structure

## Commands
```bash
go build ./...                           # Build
go test ./... -race                      # Run all tests (36 tests)
go test ./... -race -coverprofile=c.out  # Tests with coverage
golangci-lint run                        # Lint
make build / make test / make lint       # Makefile shortcuts
mcpsec scan <file-or-dir>               # Scan a config
mcpsec scan --format json <file>        # OCSF JSON output
mcpsec scan --severity critical <file>  # Filter by severity
mcpsec scan --input-format dxt <file>   # Force input format
mcpsec rules list                        # List YAML rules
mcpsec rules validate <rule.yaml>       # Validate a rule file
```

## Testing Conventions
- Table-driven tests with testify assertions
- testdata/vulnerable-server.json must trigger all 10 OWASP MCP categories (15 findings)
- testdata/safe-server.json must trigger zero findings
- testdata/dxt-manifest.json tests DXT format auto-detection
- All tests must pass with `-race` flag

## OWASP MCP Top 10 Mapping
| Check File              | OWASP | Description                      |
|------------------------|-------|----------------------------------|
| prompt_injection.go    | MCP01 | Prompt Injection via Tool Output |
| permissions.go         | MCP02 | Excessive Tool Permissions       |
| auth.go                | MCP03 | Missing Authentication           |
| secrets.go             | MCP04 | Sensitive Data Exposure          |
| unsafe_resource.go     | MCP05 | Unsafe Resource Access (SSRF)    |
| tool_spoofing.go       | MCP06 | Tool Definition Spoofing         |
| transport.go           | MCP07 | Insecure Transport               |
| schema.go              | MCP08 | Unvalidated Tool Input Schemas   |
| audit_logging.go       | MCP09 | Logging/Audit Deficiencies       |
| resource_exhaustion.go | MCP10 | Denial of Service                |

## GitHub
- Repo: github.com/pfrederiksen/mcpsec
- Branch protection on main: require PR + passing CI
- CI: go vet + staticcheck + golangci-lint + go test -race
- Releases: GoReleaser on tag push (v*)

## Style Preferences
- Keep checks focused and minimal -- one file per OWASP risk
- Prefer table-driven tests
- Use OCSF field names in output structs
- Rule IDs follow pattern: MCPxx-xxx (e.g., MCP04-001)
- YAML rule IDs follow pattern: MCPxx-Rxx (e.g., MCP04-R01)
- Per-tool findings are deduplicated (one finding with count, not N separate findings)
- Never commit secrets or test fixtures containing real credentials
