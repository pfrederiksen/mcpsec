package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pfrederiksen/mcpsec/internal/config"
	"github.com/pfrederiksen/mcpsec/internal/output"
	"github.com/pfrederiksen/mcpsec/internal/rules"
	"github.com/pfrederiksen/mcpsec/internal/scanner"
	bundled "github.com/pfrederiksen/mcpsec/rules"
	"github.com/spf13/cobra"
)

var errFindingsThreshold = errors.New("findings met failure threshold")

var validSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

func validateChoice(flag, value string, valid map[string]bool) error {
	if !valid[strings.ToLower(strings.TrimSpace(value))] {
		return fmt.Errorf("invalid value for --%s: %q", flag, value)
	}
	return nil
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mcpsec",
		Short: "MCPSec Audit - OWASP MCP Top 10 security scanner",
		Long:  "Security scanner for Model Context Protocol configurations, remote tool inventories, and server source code, aligned to the OWASP MCP Top 10:2025 beta.",
	}

	var configPath string
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Policy file (default: ./mcpsec.yaml when present)")

	var scanEmit emitOptions
	var (
		rulesDir        string
		severityFlag    string
		ignoreFlag      string
		inputFormat     string
		baselinePath    string
		approvedServers string
	)

	scanCmd := &cobra.Command{
		Use:   "scan [config-file]",
		Short: "Scan an MCP server configuration file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault(configPath)
			if err != nil {
				return err
			}
			applyPolicy(cmd, cfg, policyFields{
				format: &scanEmit.format, output: &scanEmit.output, severity: &severityFlag, failOn: &scanEmit.failOn,
				rules: &rulesDir, splunkURL: &scanEmit.splunkURL, splunkToken: &scanEmit.splunkToken, splunkIndex: &scanEmit.splunkIndex,
				baseline: &baselinePath, inputFormat: &inputFormat, approved: &approvedServers, ignore: &ignoreFlag,
			})
			if err := validateEmit(scanEmit, severityFlag, inputFormat); err != nil {
				return err
			}
			s, err := prepareScanner(rulesDir, severityFlag, ignoreFlag, baselinePath, approvedServers, baselineKey(cfg))
			if err != nil {
				return err
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
			return emitFindings(result.Findings, scanEmit)
		},
	}

	bindEmitFlags(scanCmd, &scanEmit)
	scanCmd.Flags().StringVar(&rulesDir, "rules", "", "Custom rules directory; replaces the embedded rules")
	scanCmd.Flags().StringVar(&severityFlag, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low,info)")
	scanCmd.Flags().StringVar(&ignoreFlag, "ignore", "", "Comma-separated rule IDs to suppress")
	scanCmd.Flags().StringVar(&inputFormat, "input-format", "auto", "Input format: auto, mcpservers, dxt, dxtdir")
	scanCmd.Flags().StringVar(&baselinePath, "baseline", "", "Compare configuration with an approved baseline")
	scanCmd.Flags().StringVar(&approvedServers, "approved", "", "Comma-separated approved server names; flag all others as shadow MCP")

	baselineCmd := &cobra.Command{Use: "baseline", Short: "Create approved configuration fingerprints"}
	var baselineOutput string
	baselineCreateCmd := &cobra.Command{
		Use: "create [config-file]", Short: "Create a drift-detection baseline", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if baselineOutput == "" {
				return fmt.Errorf("--output is required")
			}
			cfg, err := config.LoadDefault(configPath)
			if err != nil {
				return err
			}
			s := scanner.New()
			s.BaselineKey = baselineKey(cfg)
			return s.CreateBaseline(args[0], baselineOutput)
		},
	}
	baselineCreateCmd.Flags().StringVarP(&baselineOutput, "output", "o", "", "Baseline output file")
	baselineCmd.AddCommand(baselineCreateCmd)

	var discoverEmit emitOptions
	discoverCmd := &cobra.Command{
		Use: "discover [path...]", Short: "Inventory MCP servers across client configurations", Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault(configPath)
			if err != nil {
				return err
			}
			applyPolicy(cmd, cfg, policyFields{
				format: &discoverEmit.format, output: &discoverEmit.output, severity: &severityFlag, failOn: &discoverEmit.failOn,
				rules: &rulesDir, splunkURL: &discoverEmit.splunkURL, splunkToken: &discoverEmit.splunkToken, splunkIndex: &discoverEmit.splunkIndex,
				approved: &approvedServers, ignore: &ignoreFlag,
			})
			if err := validateEmit(discoverEmit, severityFlag, ""); err != nil {
				return err
			}
			s, err := prepareScanner(rulesDir, severityFlag, ignoreFlag, "", approvedServers, nil)
			if err != nil {
				return err
			}
			found, err := s.Discover(args)
			if err != nil {
				return err
			}
			if approvedServers != "" {
				findings := scanner.ShadowFindings(found, splitList(approvedServers))
				filtered := make([]scanner.Finding, 0, len(findings))
				for _, finding := range findings {
					if s.Allows(finding) {
						filtered = append(filtered, finding)
					}
				}
				return emitFindings(filtered, discoverEmit)
			}
			enc := json.NewEncoder(os.Stdout)
			var outFile *os.File
			if discoverEmit.output != "" {
				created, createErr := os.Create(filepath.Clean(discoverEmit.output))
				if createErr != nil {
					return createErr
				}
				outFile = created
				enc = json.NewEncoder(outFile)
			}
			enc.SetIndent("", "  ")
			encodeErr := enc.Encode(found)
			if outFile == nil {
				return encodeErr
			}
			closeErr := outFile.Close()
			if encodeErr != nil {
				return encodeErr
			}
			return closeErr
		},
	}
	bindEmitFlags(discoverCmd, &discoverEmit)
	discoverCmd.Flags().StringVar(&approvedServers, "approved", "", "Comma-separated approved server names; flag all others as shadow MCP")
	discoverCmd.Flags().StringVar(&severityFlag, "severity", "", "Filter shadow findings by severity")
	discoverCmd.Flags().StringVar(&ignoreFlag, "ignore", "", "Comma-separated rule IDs to suppress")

	var activeEmit emitOptions
	var activeAllowPrivate bool
	var activeTokenEnv string
	activeCmd := &cobra.Command{
		Use: "active [MCP-URL]", Short: "Safely enumerate and scan a remote MCP server", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault(configPath)
			if err != nil {
				return err
			}
			applyPolicy(cmd, cfg, policyFields{
				format: &activeEmit.format, output: &activeEmit.output, severity: &severityFlag, failOn: &activeEmit.failOn,
				rules: &rulesDir, splunkURL: &activeEmit.splunkURL, splunkToken: &activeEmit.splunkToken, splunkIndex: &activeEmit.splunkIndex,
				ignore: &ignoreFlag,
			})
			if err := validateEmit(activeEmit, severityFlag, ""); err != nil {
				return err
			}
			s, err := prepareScanner(rulesDir, severityFlag, ignoreFlag, "", "", nil)
			if err != nil {
				return err
			}
			if activeTokenEnv != "" {
				s.ActiveToken = os.Getenv(activeTokenEnv)
			}
			result, err := s.ActiveScan(context.Background(), args[0], activeAllowPrivate)
			if err != nil {
				return err
			}
			return emitFindings(result.Findings, activeEmit)
		},
	}
	bindEmitFlags(activeCmd, &activeEmit)
	activeCmd.Flags().BoolVar(&activeAllowPrivate, "allow-private", false, "Allow explicitly authorized private/local and HTTP endpoints")
	activeCmd.Flags().StringVar(&activeTokenEnv, "token-env", "MCPSEC_ACTIVE_TOKEN", "Environment variable containing a bearer token")
	activeCmd.Flags().StringVar(&severityFlag, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low,info)")
	activeCmd.Flags().StringVar(&ignoreFlag, "ignore", "", "Comma-separated rule IDs to suppress")
	activeCmd.Flags().StringVar(&rulesDir, "rules", "", "Custom rules directory; replaces the embedded rules")

	var sourceEmit emitOptions
	sourceCmd := &cobra.Command{
		Use: "source [directory]", Short: "Scan MCP server source code without executing it", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault(configPath)
			if err != nil {
				return err
			}
			applyPolicy(cmd, cfg, policyFields{
				format: &sourceEmit.format, output: &sourceEmit.output, severity: &severityFlag, failOn: &sourceEmit.failOn,
				ignore: &ignoreFlag,
			})
			if err := validateEmit(sourceEmit, severityFlag, ""); err != nil {
				return err
			}
			s, err := prepareScanner("", severityFlag, ignoreFlag, "", "", nil)
			if err != nil {
				return err
			}
			result, err := s.ScanSource(args[0])
			if err != nil {
				return err
			}
			return emitFindings(result.Findings, sourceEmit)
		},
	}
	bindEmitFlags(sourceCmd, &sourceEmit)
	sourceCmd.Flags().StringVar(&severityFlag, "severity", "", "Filter by severity (comma-separated: critical,high,medium,low,info)")
	sourceCmd.Flags().StringVar(&ignoreFlag, "ignore", "", "Comma-separated rule IDs to suppress")

	// rules command
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage security rules",
	}

	rulesListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all loaded rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			var loaded []*rules.Rule
			var err error
			if rulesDir == "" {
				loaded, err = rules.LoadFS(bundled.Files)
			} else {
				loaded, err = rules.LoadDirectory(rulesDir)
			}
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
				return fmt.Errorf("rule validation failed: %s", strings.Join(errors, "; "))
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

	rootCmd.AddCommand(scanCmd, baselineCmd, discoverCmd, activeCmd, sourceCmd, rulesCmd, versionCmd)

	rootCmd.SilenceUsage = true
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func findingInputs(findings []scanner.Finding) []output.FindingInput {
	result := make([]output.FindingInput, len(findings))
	for i, f := range findings {
		result[i] = output.FindingInput{RuleID: f.RuleID, Name: f.Name, Severity: f.Severity, Description: f.Description, Remediation: f.Remediation, Resource: f.Resource, OWASPMCP: f.OWASPMCP, Location: f.Location, Line: f.Line}
	}
	return result
}
