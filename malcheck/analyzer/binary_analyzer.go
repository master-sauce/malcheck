// binary_analyzer.go
package analyzer

import (
	"fmt"
	"os/exec"
	"strings"
)

// AnalyzeBinary runs strings on a binary file and checks against rules
func AnalyzeBinary(path string, rules []Rule, minSev Severity) FileResult {
	fr := FileResult{Path: path}

	// Run strings command on the binary
	cmd := exec.Command("strings", "-n", "4", path) // Only include strings 4 chars or longer
	output, err := cmd.Output()
	if err != nil {
		fr.Error = fmt.Errorf("strings command failed: %v", err)
		return fr
	}

	// Convert output to lines for analysis
	lines := strings.Split(string(output), "\n")
	lineNum := 0

	for _, line := range lines {
		lineNum++
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, rule := range rules {
			if rule.Severity < minSev {
				continue
			}
			col, matched := rule.Match(line)
			if matched {
				fr.Findings = append(fr.Findings, Finding{
					File:     path,
					Line:     lineNum,
					Column:   col,
					Content:  line,
					RuleID:   rule.ID,
					RuleName: rule.Name,
					Category: rule.Category,
					Severity: rule.Severity,
					Details:  rule.Details,
				})
			}
		}
	}

	return fr
}
