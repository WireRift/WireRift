// Package diag prints the step-by-step output shared by the "doctor" commands.
package diag

import (
	"fmt"
	"io"
)

// Outcomes of one check.
const (
	OK = iota
	Warn
	Fail
)

// Report prints one line per diagnostic step and counts problems.
type Report struct {
	Out      io.Writer
	Warnings int
	Failures int
}

// Add prints a result. The hint (how to fix it) is shown for warnings and failures.
func (r *Report) Add(status int, name, detail, hint string) {
	mark := "✓"
	switch status {
	case Warn:
		mark = "!"
		r.Warnings++
	case Fail:
		mark = "✗"
		r.Failures++
	}
	fmt.Fprintf(r.Out, "  %s  %-16s %s\n", mark, name, detail)
	if hint != "" && status != OK {
		fmt.Fprintf(r.Out, "     %-16s → %s\n", "", hint)
	}
}

// Summary prints the closing line and returns the number of failures.
func (r *Report) Summary() int {
	switch {
	case r.Failures > 0:
		fmt.Fprintf(r.Out, "\n%d problem(s) found.\n", r.Failures)
	case r.Warnings > 0:
		fmt.Fprintf(r.Out, "\nNo failures, %d warning(s).\n", r.Warnings)
	default:
		fmt.Fprintln(r.Out, "\nAll checks passed.")
	}
	return r.Failures
}
