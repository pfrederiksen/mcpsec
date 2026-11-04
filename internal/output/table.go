package output

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// WriteTable writes findings as a human-readable table to the given writer.
func WriteTable(w io.Writer, findings []FindingInput) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}

	// Column widths
	idW, nameW, sevW, owaspW, resW := 12, 42, 10, 8, 30

	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s", idW, "RULE ID", nameW, "NAME", sevW, "SEVERITY", owaspW, "OWASP", resW, "RESOURCE")
	separator := strings.Repeat("-", idW+nameW+sevW+owaspW+resW+4)

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
		id := sanitizeCell(f.RuleID)
		name := sanitizeCell(f.Name)
		if len(name) > nameW {
			name = name[:nameW-3] + "..."
		}
		resource := sanitizeCell(f.Resource)
		if len(resource) > resW {
			resource = resource[:resW-3] + "..."
		}
		label := strings.ToUpper(f.Severity)
		pad := sevW - len(label)
		if pad < 0 {
			pad = 0
		}
		sev := label
		if shouldColor(w) {
			sev = colorSeverity(f.Severity)
		}
		owasp := f.OWASPMCP
		if owasp == "" {
			owasp = "-"
		}
		if _, err := fmt.Fprintf(w, "%-*s %-*s %s%s %-*s %-*s\n", idW, id, nameW, name, sev, strings.Repeat(" ", pad), owaspW, owasp, resW, resource); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, separator); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Total: %d finding(s)\n", len(findings))
	return err
}

func sanitizeCell(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}

func shouldColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
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
