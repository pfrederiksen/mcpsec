package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pfrederiksen/mcpsec/internal/output"
	"github.com/pfrederiksen/mcpsec/internal/rules"
	"github.com/pfrederiksen/mcpsec/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mcpsec",
		Short: "MCPSec Audit - OWASP MCP Top 10 security scanner",
		Long:  "Security scanner that audits Model Context Protocol (MCP) server configurations against the OWASP MCP Top 10.",
	}

	// scan command
	var (
		formatFlag    string
		outputFlag    string
		rulesDir      string
		severityFlag  string
		splunkURL     string
		splunkToken   string
		splunkIndex   string
		failOn        string
		quiet         bool
		inputFormat   string
	)

	scanCmd := &cobra.Command{
		Use:   "scan [config-file]",
		Short: "Scan an MCP server configuration file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (retErr error) {
			s := scanner.New()

			if rulesDir != "" {
				cleanDir := filepath.Clean(rulesDir)
				info, err := os.Stat(cleanDir)
				if err != nil {
					return fmt.Errorf("rules directory: %w", err)
				}
				if !info.IsDir() {
					return fmt.Errorf("rules path is not a directory: %s", cleanDir)
				}
				if err := s.LoadRules(cleanDir); err != nil {
					return fmt.Errorf("loading rules: %w", err)
				}
			}

			if severityFlag != "" {
				s.Severity = strings.Split(severityFlag, ",")
			}

			switch strings.ToLower(inputFormat) {
			case "dxt":
				s.InputFormat = scanner.FormatDXT
			case "dxtdir":
				s.InputFormat = scanner.FormatDXTDir
			case "mcpservers":
				s.InputFormat = scanner.FormatMCPServers
			default:
				s.InputFormat = scanner.FormatAuto
			}

			result, err := s.ScanFile(args[0])
			if err != nil {
				return err
			}

			findings := make([]output.FindingInput, len(result.Findings))
			for i, f := range result.Findings {
				findings[i] = output.FindingInput{
					RuleID:      f.RuleID,
					Name:        f.Name,
					Severity:    f.Severity,
					Description: f.Description,
					Remediation: f.Remediation,
					Resource:    f.Resource,
				}
			}

			w := os.Stdout
			if outputFlag != "" {
				cleanPath := filepath.Clean(outputFlag)
				// Verify output directory exists and is writable
				outDir := filepath.Dir(cleanPath)
				if info, err := os.Stat(outDir); err != nil || !info.IsDir() {
					return fmt.Errorf("output directory does not exist: %s", outDir)
				}
				f, err := os.Create(cleanPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer func() {
					if cerr := f.Close(); cerr != nil && retErr == nil {
						retErr = cerr
					}
				}()
				w = f
			}

			switch strings.ToLower(formatFlag) {
			case "json":
				if err := output.WriteOCSF(w, findings, version); err != nil {
					return err
				}
			case "splunk":
				token := splunkToken
				if token != "" {
					_, _ = fmt.Fprintln(os.Stderr, "Warning: --splunk-token is visible in process listings; prefer MCPSEC_SPLUNK_TOKEN env var")
				}
				if token == "" {
					token = os.Getenv("MCPSEC_SPLUNK_TOKEN")
				}
				if splunkURL != "" && token != "" {
					if err := output.ValidateHECURL(splunkURL); err != nil {
						return err
					}
					if err := output.WriteSplunk(findings, version, splunkURL, token, splunkIndex); err != nil {
						return err
					}
					if !quiet {
						_, _ = fmt.Fprintf(os.Stderr, "Sent %d finding(s) to Splunk HEC\n", len(findings))
					}
				} else {
					if err := output.WriteSplunkToWriter(w, findings, version); err != nil {
						return err
					}
				}
			default:
				if !quiet {
					if err := output.WriteTable(w, findings); err != nil {
						return err
					}
				}
			}

			if failOn != "" {
				severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
				threshold, ok := severityOrder[strings.ToLower(failOn)]
				if !ok {
					return fmt.Errorf("invalid severity for --fail-on: %s", failOn)
				}
				for _, f := range result.Findings {
					if sev, ok := severityOrder[strings.ToLower(f.Severity)]; ok && sev <= threshold {
						os.Exit(1)
					}
				}
			}

			return nil
		},
	}

	scanCmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format: table, json, splunk")
	scanCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path (default: stdout)")
	scanCmd.Flags().StringVar(&rulesDir, "rules", "", "Custom rules directory")
	scanCmd.Flags().StringVar(&severityFlag, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low,info)")
	scanCmd.Flags().StringVar(&splunkURL, "splunk-url", "", "Splunk HEC endpoint URL")
	scanCmd.Flags().StringVar(&splunkToken, "splunk-token", "", "Splunk HEC token")
	scanCmd.Flags().StringVar(&splunkIndex, "splunk-index", "", "Splunk index name")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 1 if findings at or above this severity")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress output except findings")
	scanCmd.Flags().StringVar(&inputFormat, "input-format", "auto", "Input format: auto, mcpservers, dxt, dxtdir")

	// rules command
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage security rules",
	}

	rulesListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all loaded rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := rulesDir
			if dir == "" {
				dir = "rules"
			}
			loaded, err := rules.LoadDirectory(dir)
			if err != nil {
				return err
			}
			fmt.Printf("%-12s %-50s %-10s %s\n", "ID", "NAME", "SEVERITY", "OWASP")
			fmt.Println(strings.Repeat("-", 90))
			for _, r := range loaded {
				name := r.Name
				if len(name) > 50 {
					name = name[:47] + "..."
				}
				fmt.Printf("%-12s %-50s %-10s %s\n", r.ID, name, r.Severity, r.OWASPMCP)
			}
			return nil
		},
	}

	rulesValidateCmd := &cobra.Command{
		Use:   "validate [rule.yaml]",
		Short: "Validate a rule file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule, err := rules.LoadFile(args[0])
			if err != nil {
				return err
			}
			errors := rules.ValidateRule(rule)
			if len(errors) > 0 {
				fmt.Println("Validation errors:")
				for _, e := range errors {
					fmt.Printf("  - %s\n", e)
				}
				os.Exit(1)
			}
			fmt.Printf("Rule %s (%s) is valid.\n", rule.ID, rule.Name)
			return nil
		},
	}

	rulesListCmd.Flags().StringVar(&rulesDir, "rules", "", "Rules directory")
	rulesCmd.AddCommand(rulesListCmd, rulesValidateCmd)

	// version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("mcpsec %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}

	rootCmd.AddCommand(scanCmd, rulesCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
