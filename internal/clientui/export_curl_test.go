package clientui

// Regression tests for the "Copy as curl" export. exportCurl is JavaScript
// served inside the client interface page; its output is pasted into an
// operator shell, so every attacker-controlled interpolation (the captured
// method, the path, the header names and values, the body) must be
// shell-quoted.
//
// The captured method is the visitor's own HTTP request-line method: the edge
// serializes r.Method verbatim, the client relay parses it back and records it
// on the exchange, and the interface shows it. A method is an RFC 9110 token,
// and the token character set includes the shell metacharacters ` and $ — so an
// unquoted method let a visitor run a command in the operator's shell.
// The dashboard's twin feature was hardened for the same class of bug
// (internal/dashboard, shSingle + export_curl_test.go); this copy of the
// feature was not.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/client"
)

// servedClientUIJS returns the q1/curl JavaScript exactly as the client
// interface serves it.
func servedClientUIJS(t *testing.T) string {
	t.Helper()

	mgr := NewManager(client.DefaultConfig(), nil, nil)
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	h := NewHandler(mgr, key, "test")

	// The page sits behind the launch key: GET /?k=<key> sets the cookie.
	req := httptest.NewRequest(http.MethodGet, "/?k="+key, nil)
	req.Host = "127.0.0.1:4041"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if len(rec.Result().Cookies()) == 0 {
		t.Fatalf("no launch cookie set (status %d)", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "127.0.0.1:4041"
	for _, c := range rec.Result().Cookies() {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("client interface index = %d, want %d", rec2.Code, http.StatusOK)
	}
	html := rec2.Body.String()

	start := strings.Index(html, "function q1")
	if start < 0 {
		t.Fatalf("served client interface does not define q1; shell escaping missing")
	}
	end := strings.Index(html[start:], "function replay")
	if end < 0 {
		t.Fatalf("served client interface has no replay() after q1/curl")
	}
	return html[start : start+end]
}

// TestExportCurlQuotesEveryInterpolation pins the structural contract: every
// interpolated argument goes through the shell-quoting helper q1.
func TestExportCurlQuotesEveryInterpolation(t *testing.T) {
	js := servedClientUIJS(t)
	for _, want := range []string{
		`q1(d.method||'GET')`,
		`q1('http://'+d.local+d.path)`,
		`q1(k+': '+v)`,
		`q1(d.request.body)`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("export missing shell-quoted interpolation %q; a visitor-controlled "+
				"method or header value would break out of the exported command", want)
		}
	}
	if !strings.Contains(js, `replace(/'/g,"'\\''")`) {
		t.Errorf("q1 does not escape embedded single quotes as '\\''")
	}
}

// TestExportCurlGeneratedCommandIsShellSafe executes the served export on a
// malicious fixture and runs the generated command through /bin/sh. The
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

	// A legal RFC 9110 token method (backtick, $ and . are tchar) that runs a
	// command in the operator's shell when the exported command is pasted:
	// $IFS expands to whitespace, so "touch$IFS.pwned.txt" runs
	// "touch .pwned.txt" in the shell's working directory.
	maliciousMethod := "`touch$IFS.pwned.txt`"

	fixtures := `
var d = {kind:'http', method: %q, local:'127.0.0.1:9999', path:'/x',
         request:{headers:{}, body:''}};
require('fs').writeFileSync('malicious.cmd', curl(d));
var b = {kind:'http', method: 'GET', local:'127.0.0.1:9999', path:'/x',
         request:{headers:{'X-Test':['v']}, body:''}};
require('fs').writeFileSync('benign.cmd', curl(b));
`
	harness := servedClientUIJS(t) + strings.Replace(fixtures, "%q", "'"+maliciousMethod+"'", 1)
	if err := os.WriteFile(filepath.Join(dir, "harness.js"), []byte(harness), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	cmd := exec.Command(jsRuntime, filepath.Join(dir, "harness.js"))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run export harness: %v; output: %s", err, out)
	}

	benign, err := os.ReadFile(filepath.Join(dir, "benign.cmd"))
	if err != nil {
		t.Fatalf("read benign command: %v", err)
	}
	// The benign export keeps the method (quoted or not) and the URL.
	if !regexp.MustCompile(`-X '?GET'?`).MatchString(string(benign)) {
		t.Errorf("benign export lost the method: %q", string(benign))
	}
	if !strings.Contains(string(benign), "127.0.0.1:9999/x") {
		t.Errorf("benign export lost the URL: %q", string(benign))
	}

	malicious, err := os.ReadFile(filepath.Join(dir, "malicious.cmd"))
	if err != nil {
		t.Fatalf("read malicious command: %v", err)
	}

	// Control: the benign command runs without side effects.
	benignRun := exec.Command(sh, "-c", string(benign))
	benignRun.Dir = dir
	if out, err := benignRun.CombinedOutput(); err != nil {
		t.Logf("control: benign command exited %v (curl may be absent): %s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".pwned.txt")); statErr == nil {
		t.Fatalf("control broken: benign export created .pwned.txt")
	}

	// Defect assertion: the exported command must not execute injected shell.
	maliciousRun := exec.Command(sh, "-c", string(malicious))
	maliciousRun.Dir = dir
	if out, err := maliciousRun.CombinedOutput(); err != nil {
		t.Logf("malicious command exited %v (curl may be absent): %s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".pwned.txt")); statErr == nil {
		t.Fatalf("exported cURL command executed injected shell code (.pwned.txt created) " +
			"— the captured method must be shell-quoted")
	}
}

// TestCapturedMethodIsRecordedVerbatim pins why the export has to quote the
// method: the interface shows the visitor's request-line method unchanged, so
// the shell-quoting in the export is the only thing standing between a
// visitor and the operator's shell.
func TestCapturedMethodIsRecordedVerbatim(t *testing.T) {
	mgr := NewManager(client.DefaultConfig(), nil, nil)

	const method = "`touch$IFS.pwned.txt`"
	mgr.record(client.Exchange{
		ID: 1, Kind: "http", Method: method, Path: "/x", LocalAddr: "127.0.0.1:9999",
	})

	rows, _ := mgr.Traffic(0)
	if len(rows) != 1 {
		t.Fatalf("recorded rows = %d, want 1", len(rows))
	}
	if rows[0].Method != method {
		t.Errorf("recorded method = %q, want the visitor's method verbatim %q", rows[0].Method, method)
	}

	d, ok := mgr.Detail(rows[0].ID)
	if !ok {
		t.Fatal("detail not found for the recorded exchange")
	}
	if d.Method != method {
		t.Errorf("detail method = %q, want %q", d.Method, method)
	}
}
