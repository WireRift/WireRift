package dashboard

// Regression tests for the cURL export feature. exportCurl is JavaScript
// served inside the dashboard page; its output is pasted into an operator
// shell, so every attacker-controlled interpolation (method, header names
// and values, body, path) must be shell-quoted. Before the fix, only the
// body was escaped: a request header containing a single quote broke out of
// the quoted -H argument and executed extra shell commands when the operator
// ran the exported command.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/server"
)

// servedDashboardJS returns the exportCurl/shSingle JavaScript exactly as the
// dashboard serves it.
func servedDashboardJS(t *testing.T) string {
	t.Helper()
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	d := New(Config{Server: srv, AuthManager: authMgr})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	d.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard index = %d, want %d", rec.Code, http.StatusOK)
	}
	html := rec.Body.String()

	start := strings.Index(html, "function shSingle")
	if start < 0 {
		t.Fatalf("served dashboard does not define shSingle; exportCurl shell escaping missing")
	}
	endMarker := "toast('cURL command copied', 'ok');"
	end := strings.Index(html[start:], endMarker)
	if end < 0 {
		t.Fatalf("served dashboard exportCurl body not found")
	}
	close := strings.Index(html[start+end:], "\n}")
	if close < 0 {
		t.Fatalf("served dashboard exportCurl closing brace not found")
	}
	return html[start : start+end+close+2]
}

// TestExportCurlQuotesEveryInterpolation pins the structural contract: every
// interpolated argument goes through the shSingle shell-quoting helper.
func TestExportCurlQuotesEveryInterpolation(t *testing.T) {
	js := servedDashboardJS(t)
	for _, want := range []string{
		`'curl -X ' + shSingle(r.method || 'GET')`,
		`' -H ' + shSingle(hKeys[i] + ': ' + r.req_headers[hKeys[i]])`,
		`' -d ' + shSingle(body)`,
		`' ' + shSingle(r.path || '/')`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("exportCurl missing shell-quoted interpolation %q; header/path values with single quotes would break out of the exported command", want)
		}
	}
	if !strings.Contains(js, `replace(/'/g, "'\\''")`) {
		t.Errorf("shSingle does not escape embedded single quotes as '\\''")
	}
}

// TestExportCurlGeneratedCommandIsShellSafe executes the served exportCurl on
// a malicious fixture and runs the generated command through /bin/sh. The
// injected side-effect file must NOT be created. Skipped when no JS runtime
// or POSIX shell is available (reported as skipped, not passed).
func TestExportCurlGeneratedCommandIsShellSafe(t *testing.T) {
	jsRuntime := ""
	for _, rt := range []string{"node", "bun"} {
		if p, err := exec.LookPath(rt); err == nil {
			jsRuntime = p
			break
		}
	}
	sh, err := exec.LookPath("sh")
	if jsRuntime == "" || err != nil {
		t.Skipf("behavioral check needs a JS runtime (node/bun) and sh; found js=%q sh=%q", jsRuntime, sh)
	}

	dir := t.TempDir()
	stubs := `var generated = [];
function copyToClipboard(cmd){ generated.push(cmd); }
function toast(){}
var requestsCache = [
  { method: 'GET', path: '/ok', req_headers: { 'X-Benign': 'hello' } },
  { method: 'GET', path: '/x', req_headers: { 'X-Exploit': "'; echo PWNED_MARKER > pwned.txt; echo '" } }
];
`
	js := servedDashboardJS(t)
	invoke := `exportCurl(0);
exportCurl(1);
require('fs').writeFileSync('benign.cmd', generated[0]);
require('fs').writeFileSync('malicious.cmd', generated[1]);
`
	harness := stubs + js + "\n" + invoke
	if err := os.WriteFile(filepath.Join(dir, "harness.js"), []byte(harness), 0600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	cmd := exec.Command(jsRuntime, filepath.Join(dir, "harness.js"))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run exportCurl harness: %v; output: %s", err, out)
	}

	benign, err := os.ReadFile(filepath.Join(dir, "benign.cmd"))
	if err != nil {
		t.Fatalf("read benign command: %v", err)
	}
	if !strings.Contains(string(benign), "X-Benign: hello") || !strings.Contains(string(benign), "/ok") {
		t.Errorf("benign export lost its arguments: %q", string(benign))
	}

	malicious, err := os.ReadFile(filepath.Join(dir, "malicious.cmd"))
	if err != nil {
		t.Fatalf("read malicious command: %v", err)
	}
	// Control: the benign command runs without side effects.
	if out, err := exec.Command(sh, "-c", string(benign)).CombinedOutput(); err != nil {
		t.Logf("control: benign command exited %v (curl may be absent): %s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "pwned.txt")); statErr == nil {
		t.Fatalf("control broken: benign export created pwned.txt")
	}

	// Defect assertion: the exported command must not execute injected shell.
	if out, err := exec.Command(sh, "-c", string(malicious)).CombinedOutput(); err != nil {
		t.Logf("malicious command exited %v (curl may be absent): %s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "pwned.txt")); statErr == nil {
		t.Fatalf("exported cURL command executed injected shell code (pwned.txt created) — header values must be shell-quoted")
	}
}
