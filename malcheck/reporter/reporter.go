package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"malcheck/analyzer"
)

// Reporter writes scan results in a given format
type Reporter struct {
	format      string
	outputFile  string
	minSeverity analyzer.Severity
}

func New(format, outputFile string, minSev analyzer.Severity) *Reporter {
	return &Reporter{format: format, outputFile: outputFile, minSeverity: minSev}
}

func (r *Reporter) Write(result *analyzer.ScanResult) error {
	var w io.Writer = os.Stdout
	if r.outputFile != "" {
		f, err := os.Create(r.outputFile)
		if err != nil {
			return fmt.Errorf("cannot open output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(r.format) {
	case "json":
		return r.writeJSON(w, result)
	case "csv":
		return r.writeCSV(w, result)
	default:
		return r.writeText(w, result)
	}
}

// ──────────────── TEXT ────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func severityColor(s analyzer.Severity) string {
	switch s {
	case analyzer.Critical:
		return "\033[35m" // magenta
	case analyzer.High:
		return colorRed
	case analyzer.Medium:
		return colorYellow
	default:
		return colorCyan
	}
}

func (r *Reporter) writeText(w io.Writer, result *analyzer.ScanResult) error {
	total := result.Stats.TotalFindings
	if total == 0 {
		fmt.Fprintln(w, "✅  No findings detected.")
		printStats(w, result)
		return nil
	}

	// Group files with findings
	for _, fr := range result.Files {
		if fr.Error != nil {
			fmt.Fprintf(w, "%s[ERROR]%s %s: %v\n", colorRed, colorReset, fr.Path, fr.Error)
			continue
		}
		if fr.Skipped || len(fr.Findings) == 0 {
			continue
		}

		fmt.Fprintf(w, "\n%s%s%s\n", colorBold, fr.Path, colorReset)
		fmt.Fprintln(w, strings.Repeat("─", 70))

		for _, f := range fr.Findings {
			col := severityColor(f.Severity)
			fmt.Fprintf(w, "  %s[%s]%s %-8s  %s%s%s\n",
				col, f.Severity, colorReset,
				fmt.Sprintf("L%d", f.Line),
				colorBold, f.RuleName, colorReset)
			fmt.Fprintf(w, "           %sCategory:%s %s  |  %sRule:%s %s\n",
				colorGray, colorReset, f.Category,
				colorGray, colorReset, f.RuleID)
			fmt.Fprintf(w, "           %s%s%s\n", colorGray, f.Details, colorReset)
			fmt.Fprintf(w, "           %s› %s%s\n\n", colorYellow, f.Content, colorReset)
		}
	}

	printStats(w, result)
	return nil
}

func printStats(w io.Writer, result *analyzer.ScanResult) {
	s := result.Stats
	fmt.Fprintf(w, "\n%s── Scan Summary ──%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "  Files scanned : %d\n", s.FilesScanned)
	fmt.Fprintf(w, "  Files skipped : %d\n", s.FilesSkipped)
	fmt.Fprintf(w, "  Errors        : %d\n", s.FilesErrored)
	fmt.Fprintf(w, "  Total findings: %d\n", s.TotalFindings)
	if s.TotalFindings > 0 {
		fmt.Fprintf(w, "  By severity   : CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d\n",
			s.BySeverity["CRITICAL"],
			s.BySeverity["HIGH"],
			s.BySeverity["MEDIUM"],
			s.BySeverity["LOW"])
	}
}

// ──────────────── JSON ────────────────

type jsonOutput struct {
	Stats    analyzer.Stats     `json:"stats"`
	Findings []jsonFinding      `json:"findings"`
	Errors   []jsonError        `json:"errors,omitempty"`
}

type jsonFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
	Details  string `json:"details"`
	Content  string `json:"content"`
}

type jsonError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

func (r *Reporter) writeJSON(w io.Writer, result *analyzer.ScanResult) error {
	out := jsonOutput{Stats: result.Stats}

	for _, fr := range result.Files {
		if fr.Error != nil {
			out.Errors = append(out.Errors, jsonError{File: fr.Path, Error: fr.Error.Error()})
			continue
		}
		for _, f := range fr.Findings {
			out.Findings = append(out.Findings, jsonFinding{
				File:     f.File,
				Line:     f.Line,
				Column:   f.Column,
				Severity: f.Severity.String(),
				RuleID:   f.RuleID,
				RuleName: f.RuleName,
				Category: f.Category,
				Details:  f.Details,
				Content:  f.Content,
			})
		}
	}

	// Sort by severity desc
	sort.Slice(out.Findings, func(i, j int) bool {
		si := analyzer.ParseSeverity(out.Findings[i].Severity)
		sj := analyzer.ParseSeverity(out.Findings[j].Severity)
		return si > sj
	})

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ──────────────── CSV ────────────────

func (r *Reporter) writeCSV(w io.Writer, result *analyzer.ScanResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{"file", "line", "column", "severity", "rule_id", "rule_name", "category", "details", "content"})

	for _, fr := range result.Files {
		if fr.Skipped || fr.Error != nil {
			continue
		}
		for _, f := range fr.Findings {
			_ = cw.Write([]string{
				f.File,
				fmt.Sprintf("%d", f.Line),
				fmt.Sprintf("%d", f.Column),
				f.Severity.String(),
				f.RuleID,
				f.RuleName,
				f.Category,
				f.Details,
				f.Content,
			})
		}
	}
	return cw.Error()
}
