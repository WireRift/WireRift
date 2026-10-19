package diag

import (
	"strings"
	"testing"
)

func TestReportCountsAndFormats(t *testing.T) {
	var out strings.Builder
	r := &Report{Out: &out}
	r.Add(OK, "DNS", "fine", "never shown")
	r.Add(Warn, "TLS", "expires soon", "renew it")
	r.Add(Fail, "Auth", "denied", "check the token")
	got := out.String()
	for _, want := range []string{"✓  DNS", "!  TLS", "✗  Auth", "→ renew it", "→ check the token"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "never shown") {
		t.Error("hints must only be printed for warnings and failures")
	}
	if r.Warnings != 1 || r.Failures != 1 {
		t.Errorf("warnings=%d failures=%d", r.Warnings, r.Failures)
	}
	if n := r.Summary(); n != 1 || !strings.Contains(out.String(), "1 problem(s) found.") {
		t.Errorf("summary: %d\n%s", n, out.String())
	}
}

func TestSummaryVariants(t *testing.T) {
	var out strings.Builder
	(&Report{Out: &out}).Summary()
	(&Report{Out: &out, Warnings: 2}).Summary()
	if !strings.Contains(out.String(), "All checks passed.") || !strings.Contains(out.String(), "2 warning(s)") {
		t.Errorf("output:\n%s", out.String())
	}
}
