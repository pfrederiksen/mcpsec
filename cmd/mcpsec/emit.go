package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pfrederiksen/mcpsec/internal/config"
	"github.com/pfrederiksen/mcpsec/internal/output"
	"github.com/pfrederiksen/mcpsec/internal/scanner"
	"github.com/spf13/cobra"
)

type emitOptions struct {
	format        string
	output        string
	splunkURL     string
	splunkToken   string
	splunkIndex   string
	failOn        string
	summaryOutput string
	quiet         bool
}

func bindEmitFlags(cmd *cobra.Command, opt *emitOptions) {
	cmd.Flags().StringVarP(&opt.format, "format", "f", "table", "Output format: table, json, sarif, splunk")
	cmd.Flags().StringVarP(&opt.output, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&opt.splunkURL, "splunk-url", "", "Splunk HEC endpoint URL")
	cmd.Flags().StringVar(&opt.splunkToken, "splunk-token", "", "Splunk HEC token")
	cmd.Flags().StringVar(&opt.splunkIndex, "splunk-index", "", "Splunk index name")
	cmd.Flags().StringVar(&opt.failOn, "fail-on", "", "Exit with code 1 if findings at or above this severity")
	cmd.Flags().StringVar(&opt.summaryOutput, "summary-output", "", "Write a JSON scan summary to this file")
	cmd.Flags().BoolVarP(&opt.quiet, "quiet", "q", false, "Suppress table output")
}

func emitFindings(findings []scanner.Finding, opt emitOptions) (retErr error) {
	inputs := findingInputs(findings)
	if opt.summaryOutput != "" {
		summary, err := json.Marshal(struct {
			FindingsCount int `json:"findings_count"`
		}{len(inputs)})
		if err != nil {
			return fmt.Errorf("creating summary: %w", err)
		}
		if err := os.WriteFile(filepath.Clean(opt.summaryOutput), append(summary, '\n'), 0o600); err != nil {
			return fmt.Errorf("writing summary file: %w", err)
		}
	}

	w := os.Stdout
	if opt.output != "" {
		cleanPath := filepath.Clean(opt.output)
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

	switch strings.ToLower(opt.format) {
	case "json":
		if err := output.WriteOCSF(w, inputs, version); err != nil {
			return err
		}
	case "sarif":
		if err := output.WriteSARIF(w, inputs, version); err != nil {
			return err
		}
	case "splunk":
		token := opt.splunkToken
		if token != "" {
			_, _ = fmt.Fprintln(os.Stderr, "Warning: --splunk-token is visible in process listings; prefer MCPSEC_SPLUNK_TOKEN env var")
		}
		if token == "" {
			token = os.Getenv("MCPSEC_SPLUNK_TOKEN")
		}
		if opt.splunkURL != "" && token != "" {
			if err := output.ValidateHECURL(opt.splunkURL); err != nil {
				return err
			}
			if err := output.WriteSplunk(inputs, version, opt.splunkURL, token, opt.splunkIndex); err != nil {
				return err
			}
			if !opt.quiet {
				_, _ = fmt.Fprintf(os.Stderr, "Sent %d finding(s) to Splunk HEC\n", len(inputs))
			}
		} else if err := output.WriteSplunkToWriter(w, inputs, version); err != nil {
			return err
		}
	default:
		if !opt.quiet {
			if err := output.WriteTable(w, inputs); err != nil {
				return err
			}
		}
	}

	if opt.failOn != "" {
		severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		threshold := severityOrder[strings.ToLower(opt.failOn)]
		for _, finding := range findings {
			if sev, ok := severityOrder[strings.ToLower(finding.Severity)]; ok && sev <= threshold {
				return errFindingsThreshold
			}
		}
	}
	return nil
}

type policyFields struct {
	format, output, severity, failOn, rules, splunkURL, splunkToken, splunkIndex, baseline, inputFormat, approved, ignore *string
}

func applyPolicy(cmd *cobra.Command, cfg *config.Config, fields policyFields) {
	if cfg == nil {
		return
	}
	set := func(name string, dest *string, value string) {
		if dest == nil || value == "" || flagChanged(cmd, name) {
			return
		}
		*dest = value
	}
	set("format", fields.format, cfg.Format)
	set("output", fields.output, cfg.Output)
	set("fail-on", fields.failOn, cfg.FailOn)
	set("rules", fields.rules, cfg.RulesDir)
	set("splunk-url", fields.splunkURL, cfg.SplunkURL)
	set("splunk-token", fields.splunkToken, cfg.SplunkToken)
	set("splunk-index", fields.splunkIndex, cfg.SplunkIndex)
	set("baseline", fields.baseline, cfg.Baseline)
	set("input-format", fields.inputFormat, cfg.InputFormat)
	if fields.severity != nil && !flagChanged(cmd, "severity") && len(cfg.Severity) > 0 {
		*fields.severity = strings.Join(cfg.Severity, ",")
	}
	if fields.approved != nil && !flagChanged(cmd, "approved") && len(cfg.Approved) > 0 {
		*fields.approved = strings.Join(cfg.Approved, ",")
	}
	if fields.ignore != nil && !flagChanged(cmd, "ignore") && len(cfg.Ignore) > 0 {
		*fields.ignore = strings.Join(cfg.Ignore, ",")
	}
}

func flagChanged(cmd *cobra.Command, name string) bool {
	flag := cmd.Flags().Lookup(name)
	return flag != nil && flag.Changed
}

func validateEmit(opt emitOptions, severity, inputFormat string) error {
	if err := validateChoice("format", opt.format, map[string]bool{"table": true, "json": true, "sarif": true, "splunk": true}); err != nil {
		return err
	}
	if inputFormat != "" {
		if err := validateChoice("input-format", inputFormat, map[string]bool{"auto": true, "mcpservers": true, "dxt": true, "dxtdir": true}); err != nil {
			return err
		}
	}
	if severity != "" {
		for _, item := range strings.Split(severity, ",") {
			if err := validateChoice("severity", item, validSeverities); err != nil {
				return err
			}
		}
	}
	if opt.failOn != "" {
		if err := validateChoice("fail-on", opt.failOn, validSeverities); err != nil {
			return err
		}
	}
	return nil
}

func prepareScanner(rulesDir, severity, ignore, baseline, approved string, key []byte) (*scanner.Scanner, error) {
	s := scanner.New()
	if rulesDir != "" {
		cleanDir := filepath.Clean(rulesDir)
		info, err := os.Stat(cleanDir)
		if err != nil {
			return nil, fmt.Errorf("rules directory: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("rules path is not a directory: %s", cleanDir)
		}
		if err := s.LoadRules(cleanDir); err != nil {
			return nil, fmt.Errorf("loading rules: %w", err)
		}
	}
	if severity != "" {
		s.Severity = splitList(severity)
	}
	s.Ignore = splitList(ignore)
	s.Approved = splitList(approved)
	s.BaselinePath = baseline
	s.BaselineKey = key
	return s, nil
}

func baselineKey(cfg *config.Config) []byte {
	name := "MCPSEC_BASELINE_KEY"
	if cfg != nil && cfg.BaselineKeyEnv != "" {
		name = cfg.BaselineKeyEnv
	}
	return []byte(os.Getenv(name))
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
