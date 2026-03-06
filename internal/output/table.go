package output

import (
	"fmt"
	"io"
	"strings"
)

// WriteTable writes findings as a human-readable table to the given writer.
func WriteTable(w io.Writer, findings []FindingInput) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}

	// Column widths
	idW, nameW, sevW, resW := 12, 45, 10, 30

	header := fmt.Sprintf("%-*s %-*s %-*s %-*s", idW, "RULE ID", nameW, "NAME", sevW, "SEVERITY", resW, "RESOURCE")
	separator := strings.Repeat("-", idW+nameW+sevW+resW+3)

	if _, err := fmt.Fprintln(w, separator); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, separator); err != nil {
		return err
	}

	for _, f := range findings {
		name := f.Name
		if len(name) > nameW {
			name = name[:nameW-3] + "..."
		}
		resource := f.Resource
		if len(resource) > resW {
			resource = resource[:resW-3] + "..."
		}
		sev := colorSeverity(f.Severity)
		if _, err := fmt.Fprintf(w, "%-*s %-*s %-*s %-*s\n", idW, f.RuleID, nameW, name, sevW, sev, resW, resource); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, separator); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Total: %d finding(s)\n", len(findings))
	return err
}

func colorSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "\033[1;31m" + strings.ToUpper(sev) + "\033[0m"
	case "high":
		return "\033[31m" + strings.ToUpper(sev) + "\033[0m"
	case "medium":
		return "\033[33m" + strings.ToUpper(sev) + "\033[0m"
	case "low":
		return "\033[36m" + strings.ToUpper(sev) + "\033[0m"
	default:
		return strings.ToUpper(sev)
	}
}
