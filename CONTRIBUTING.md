# Contributing to MCPSec

Thank you for your interest in contributing to MCPSec! We especially welcome new YAML rules -- you don't need to know Go to contribute detections.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/mcpsec.git
   cd mcpsec
   ```
3. **Create a branch** for your change:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Building

```bash
make build
# or
go build ./...
```

### Running Tests

All tests must pass before submitting a PR:

```bash
go test ./... -race
```

Or using the Makefile:

```bash
make test
```

### Linting

```bash
make lint
# or
golangci-lint run
```

### Running a Scan

```bash
# Against the test fixtures
go run ./cmd/mcpsec scan testdata/vulnerable-server.json
go run ./cmd/mcpsec scan testdata/safe-server.json

# Against a DXT extension
go run ./cmd/mcpsec scan path/to/manifest.json

# Against a Claude Extensions directory
go run ./cmd/mcpsec scan ~/Library/Application\ Support/Claude/Claude\ Extensions/
```

## Writing YAML Rules

MCPSec uses YAML-based rules for community-contributed detections. See [docs/rules-authoring.md](docs/rules-authoring.md) for the full schema and examples.

### Rule Checklist

- [ ] Rule YAML follows the schema in `docs/rules-authoring.md`
- [ ] Rule has a unique ID following the `MCPxx-Rxx` pattern
- [ ] Rule matches `testdata/vulnerable-server.json` (when applicable)
- [ ] Rule does NOT match `testdata/safe-server.json`
- [ ] `mcpsec rules validate your-rule.yaml` passes
- [ ] Rule description and remediation are clear and actionable

## Writing Go Checks

If you're adding a new Go check in `internal/checks/`:

1. Create a new file following the one-file-per-OWASP-risk convention
2. Implement the `Check` interface: `Run(ctx CheckContext) []CheckFinding`
3. Add table-driven tests in `checks_test.go`
4. Register the check in `internal/scanner/scanner.go` `New()`
5. Deduplicate per-tool findings (emit one finding with count, not N findings)

## Submitting Changes

1. Commit your changes with a clear message:
   ```bash
   git commit -m "Add rule for detecting weak cipher suites"
   ```
2. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
3. Open a **Pull Request** against the `main` branch.
4. Fill out the PR template completely.
5. Wait for CI to pass and a maintainer to review.

## Pull Request Guidelines

- Keep PRs focused on a single change.
- Include tests for new functionality.
- Update documentation if applicable.
- Reference any related issues using `Fixes #123` or `Relates to #123`.

## Issue Templates

- **Bug report**: [Bug Report](https://github.com/pfrederiksen/mcpsec/issues/new?template=bug_report.md)
- **False positive**: [False Positive](https://github.com/pfrederiksen/mcpsec/issues/new?template=false_positive.md) -- include the rule ID, config snippet, and expected vs actual behavior
- **New rule proposal**: [New Rule](https://github.com/pfrederiksen/mcpsec/issues/new?template=new_rule.md) -- propose before implementing

## Code of Conduct

Be respectful, constructive, and collaborative. We are committed to providing a welcoming and inclusive experience for everyone.

## Questions?

Open a [GitHub Discussion](https://github.com/pfrederiksen/mcpsec/discussions) or reach out to the maintainers.
