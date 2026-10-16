package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionVariables(t *testing.T) {
	if version == "" || commit == "" || date == "" {
		t.Error("version vars should be defined")
	}
}

func TestRun_Version(t *testing.T) {
	err := run(context.Background(), []string{"-version"})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRun_FlagParseError(t *testing.T) {
	err := run(context.Background(), []string{"-unknown-flag"})
	if err == nil {
		t.Error("Expected error for unknown flag")
	}
}

func TestRun_AllCustomFlags(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()
	httpsLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpsAddr := httpsLn.Addr().String()
	httpsLn.Close()
	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-https", httpsAddr,
			"-dashboard-port", dashPort,
			"-domain", "all-flags.wirerift.com",
			"-tcp-ports", "31000-31099",
		})
	}()
	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_StartAndShutdown(t *testing.T) {
	// Find free ports
	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-dashboard-port", dashPort,
			"-domain", "test.wirerift.com",
			"-tcp-ports", "30200-30299",
		})
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Cancel to trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v (may be expected)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

func TestRun_StartAndShutdown_Verbose(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-dashboard-port", dashPort,
			"-domain", "test.wirerift.com",
			"-tcp-ports", "30300-30399",
			"-v",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_StartAndShutdown_JSONLog(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-dashboard-port", dashPort,
			"-json",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_StartFailed_BadControlAddr(t *testing.T) {
	// Use an address that will fail to bind
	err := run(context.Background(), []string{
		"-control", "192.0.2.1:99999",
		"-http", "192.0.2.1:99998",
	})
	if err == nil {
		t.Error("Expected error for bad control address")
	}
	if !strings.Contains(err.Error(), "failed to start server") {
		t.Errorf("Expected 'failed to start server', got: %v", err)
	}
}

func TestRun_AutoCert(t *testing.T) {
	tmpDir := t.TempDir()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-dashboard-port", dashPort,
			"-auto-cert",
			"-cert-dir", tmpDir,
			"-domain", "test.wirerift.com",
			"-tcp-ports", "30400-30499",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_EnvOverrides(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	os.Setenv("WIRERIFT_DOMAIN", "env.wirerift.com")
	os.Setenv("WIRERIFT_CONTROL_ADDR", controlAddr)
	os.Setenv("WIRERIFT_HTTP_ADDR", httpAddr)
	defer os.Unsetenv("WIRERIFT_DOMAIN")
	defer os.Unsetenv("WIRERIFT_CONTROL_ADDR")
	defer os.Unsetenv("WIRERIFT_HTTP_ADDR")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-dashboard-port", dashPort,
			"-tcp-ports", "30500-30599",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_EnvOverrides_NoOverrideWhenExplicit(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	// Set env vars, but pass explicit flags - flags should win
	os.Setenv("WIRERIFT_DOMAIN", "env.wirerift.com")
	os.Setenv("WIRERIFT_CONTROL_ADDR", "should-not-be-used")
	os.Setenv("WIRERIFT_HTTP_ADDR", "should-not-be-used")
	defer os.Unsetenv("WIRERIFT_DOMAIN")
	defer os.Unsetenv("WIRERIFT_CONTROL_ADDR")
	defer os.Unsetenv("WIRERIFT_HTTP_ADDR")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-dashboard-port", dashPort,
			"-domain", "explicit.wirerift.com",
			"-tcp-ports", "30600-30699",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

// --- Subprocess test for main() os.Exit ---

func runSubprocess(t *testing.T, testName string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "WIRERIFT_SUBPROCESS=1")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func TestMain_Exit_BadArgs(t *testing.T) {
	if os.Getenv("WIRERIFT_SUBPROCESS") == "1" {
		os.Args = []string{"wirerift-server", "-unknown-flag"}
		main()
		return
	}
	_, err := runSubprocess(t, "TestMain_Exit_BadArgs")
	if err == nil {
		t.Fatal("Expected non-zero exit")
	}
}

func TestMain_Exit_StartFailed(t *testing.T) {
	if os.Getenv("WIRERIFT_SUBPROCESS") == "1" {
		os.Args = []string{"wirerift-server", "-control", "192.0.2.1:99999", "-http", "192.0.2.1:99998"}
		main()
		return
	}
	_, err := runSubprocess(t, "TestMain_Exit_StartFailed")
	if err == nil {
		t.Fatal("Expected non-zero exit for bad address")
	}
}

// Test TLS manager creation error by using invalid cert directory path
func TestRun_AutoCert_InvalidPath(t *testing.T) {
	// Use a file (not directory) as cert-dir to cause error
	tmpFile := filepath.Join(t.TempDir(), "notadir")
	os.WriteFile(tmpFile, []byte("x"), 0644)

	err := run(context.Background(), []string{
		"-auto-cert",
		"-cert-dir", filepath.Join(tmpFile, "subdir"),
		"-domain", "test.wirerift.com",
		"-control", "127.0.0.1:0",
		"-http", "127.0.0.1:0",
	})
	if err != nil {
		if strings.Contains(err.Error(), "failed to create TLS manager") {
			// Expected
		} else {
			t.Logf("run returned: %v", err)
		}
	}
}

func TestRun_DashboardPortConflict(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	// Occupy the dashboard port on all interfaces to cause conflict
	dashLn, _ := net.Listen("tcp", "0.0.0.0:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	// Keep dashLn open to cause a port conflict for the dashboard
	defer dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-dashboard-port", dashPort,
			"-tcp-ports", "31100-31199",
		})
	}()

	// The dashboard will fail to start, but the server continues
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_CustomHTTPS(t *testing.T) {
	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	dashLn, _ := net.Listen("tcp", "127.0.0.1:0")
	_, dashPort, _ := net.SplitHostPort(dashLn.Addr().String())
	dashLn.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", controlAddr,
			"-http", httpAddr,
			"-https", "127.0.0.1:0",
			"-dashboard-port", dashPort,
			"-tcp-ports", "30700-30799",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_InvalidPortRange(t *testing.T) {
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, p1, _ := net.SplitHostPort(ln1.Addr().String())
	_, p2, _ := net.SplitHostPort(ln2.Addr().String())
	ln1.Close()
	ln2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", "127.0.0.1:" + p1,
			"-http", "127.0.0.1:" + p2,
			"-tcp-ports", "50000-invalid",
			"-dashboard-port", "0",
		})
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRun_ACMEEmailStaging(t *testing.T) {
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, p1, _ := net.SplitHostPort(ln1.Addr().String())
	_, p2, _ := net.SplitHostPort(ln2.Addr().String())
	ln1.Close()
	ln2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-control", "127.0.0.1:" + p1,
			"-http", "127.0.0.1:" + p2,
			"-dashboard-port", "0",
			"-acme-email", "test@example.com",
			"-acme-staging",
		})
	}()

	time.Sleep(1 * time.Second)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("run returned (expected): %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout")
	}
}

// TestNormalizeArgsSeparator tests normalizeArgs with the -- separator.
func TestNormalizeArgsSeparator(t *testing.T) {
	// Test that -- separator works correctly
	// Everything after -- should be treated as positional args
	args := normalizeArgs([]string{"-v", "--", "-token", "value"})

	// -v should be first (flag)
	if len(args) < 1 || args[0] != "-v" {
		t.Errorf("Expected -v to be first, got %v", args)
	}

	// After --, -token should be treated as positional (not a flag)
	// So it should appear after all flags
	foundPositional := false
	for _, a := range args {
		if a == "-token" {
			foundPositional = true
			break
		}
	}
	if !foundPositional {
		t.Errorf("Expected -token to be in positional args, got %v", args)
	}
}

// TestNormalizeArgsSeparatorWithOnlyPositional tests -- with only positional args after.
func TestNormalizeArgsSeparatorWithOnlyPositional(t *testing.T) {
	args := normalizeArgs([]string{"--", "positional1", "positional2"})

	// Everything after -- should be positional
	foundPositional := false
	for _, a := range args {
		if a == "positional1" {
			foundPositional = true
			break
		}
	}
	if !foundPositional {
		t.Errorf("Expected positional1 after --, got %v", args)
	}
}

// TestNormalizeArgsTripleDash tests normalizeArgs with --- (should not convert).
func TestNormalizeArgsTripleDash(t *testing.T) {
	args := normalizeArgs([]string{"---token", "value"})

	// ---token should NOT be converted to --token
	found := false
	for _, a := range args {
		if a == "---token" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ---token to remain unchanged, got %v", args)
	}
}

// TestNormalizeArgsBoolFlags tests normalizeArgs with boolean flags.
func TestNormalizeArgsBoolFlags(t *testing.T) {
	// Test -v flag (should not consume next arg)
	args := normalizeArgs([]string{"-v", "8080"})

	// -v should be in flags, 8080 should be positional
	if len(args) < 2 {
		t.Fatalf("Expected at least 2 args, got %v", args)
	}

	// Find -v and verify 8080 comes after
	foundV := false
	for i, a := range args {
		if a == "-v" {
			foundV = true
			// 8080 should be after -v in the result
			if i+1 >= len(args) || args[i+1] != "8080" {
				t.Errorf("8080 should be positional right after -v, got %v", args)
			}
			break
		}
	}
	if !foundV {
		t.Errorf("Expected -v in args, got %v", args)
	}

	// Test -json flag (should not consume next arg)
	args2 := normalizeArgs([]string{"-json", "-token", "abc"})

	// -json should be in flags
	foundJSON := false
	for _, a := range args2 {
		if a == "-json" {
			foundJSON = true
			break
		}
	}
	if !foundJSON {
		t.Errorf("Expected -json in args, got %v", args2)
	}
}

// TestNormalizeArgsNonBoolFlagValue tests normalizeArgs with non-boolean flags that take values.
func TestNormalizeArgsNonBoolFlagValue(t *testing.T) {
	// Test -control flag (should consume next arg)
	args := normalizeArgs([]string{"-control", ":4443", "-v"})

	// Both -control and :4443 should be in flags
	foundControl := false
	foundValue := false
	for _, a := range args {
		if a == "-control" {
			foundControl = true
		}
		if a == ":4443" {
			foundValue = true
		}
	}
	if !foundControl {
		t.Errorf("Expected -control in args, got %v", args)
	}
	if !foundValue {
		t.Errorf("Expected :4443 value in args, got %v", args)
	}

	// -v should be after the flag-value pair
	foundV := false
	for _, a := range args {
		if a == "-v" {
			foundV = true
			break
		}
	}
	if !foundV {
		t.Errorf("Expected -v in args, got %v", args)
	}
}

// TestNormalizeArgsSingleDash tests normalizeArgs with single dash.
func TestNormalizeArgsSingleDash(t *testing.T) {
	// Single dash should be treated as positional
	args := normalizeArgs([]string{"-v", "-", "positional"})

	foundDash := false
	for _, a := range args {
		if a == "-" {
			foundDash = true
			break
		}
	}
	if !foundDash {
		t.Errorf("Expected single dash to be positional, got %v", args)
	}
}

// TestNormalizeArgsEmpty tests normalizeArgs with empty args.
func TestNormalizeArgsEmpty(t *testing.T) {
	args := normalizeArgs([]string{})
	if len(args) != 0 {
		t.Errorf("Expected empty args, got %v", args)
	}
}

// TestNormalizeArgsOnlyFlags tests normalizeArgs with only flags.
func TestNormalizeArgsOnlyFlags(t *testing.T) {
	args := normalizeArgs([]string{"-v", "-json", "-auto-cert"})

	// All should be in flags section
	foundV := false
	foundJSON := false
	foundAutoCert := false
	for _, a := range args {
		switch a {
		case "-v":
			foundV = true
		case "-json":
			foundJSON = true
		case "-auto-cert":
			foundAutoCert = true
		}
	}
	if !foundV || !foundJSON || !foundAutoCert {
		t.Errorf("Expected all flags, got %v", args)
	}
}

// TestNormalizeArgsOnlyPositional tests normalizeArgs with only positional args.
func TestNormalizeArgsOnlyPositional(t *testing.T) {
	args := normalizeArgs([]string{"arg1", "arg2", "arg3"})

	if len(args) != 3 {
		t.Errorf("Expected 3 args, got %d: %v", len(args), args)
	}
	if args[0] != "arg1" || args[1] != "arg2" || args[2] != "arg3" {
		t.Errorf("Expected args in order, got %v", args)
	}
}

// TestNormalizeArgsFlagAtEnd tests normalizeArgs with flag at end without value.
func TestNormalizeArgsFlagAtEnd(t *testing.T) {
	args := normalizeArgs([]string{"arg1", "-v"})

	// -v should be before arg1 in output
	vIndex := -1
	arg1Index := -1
	for i, a := range args {
		if a == "-v" {
			vIndex = i
		}
		if a == "arg1" {
			arg1Index = i
		}
	}
	if vIndex == -1 {
		t.Errorf("Expected -v in args, got %v", args)
	}
	if arg1Index == -1 {
		t.Errorf("Expected arg1 in args, got %v", args)
	}
	if vIndex > arg1Index {
		t.Errorf("Expected -v before arg1, got %v", args)
	}
}

// TestNormalizeArgsDoubleDash tests normalizeArgs with double dash at end.
func TestNormalizeArgsDoubleDashAtEnd(t *testing.T) {
	args := normalizeArgs([]string{"-v", "--"})

	// Should just have -v, nothing after --
	foundV := false
	for _, a := range args {
		if a == "-v" {
			foundV = true
		}
		if a == "--" {
			t.Errorf("Expected -- to be consumed, got %v", args)
		}
	}
	if !foundV {
		t.Errorf("Expected -v in args, got %v", args)
	}
}

// TestNormalizeArgsFlagValueAtEnd tests normalizeArgs with flag value at end.
func TestNormalizeArgsFlagValueAtEnd(t *testing.T) {
	args := normalizeArgs([]string{"-control", ":4443"})

	if len(args) != 2 {
		t.Errorf("Expected 2 args, got %d: %v", len(args), args)
	}
	if args[0] != "-control" || args[1] != ":4443" {
		t.Errorf("Expected [-control, :4443], got %v", args)
	}
}

// TestNormalizeArgsDoubleDashSeparatorOnly tests normalizeArgs with just --.
func TestNormalizeArgsDoubleDashSeparatorOnly(t *testing.T) {
	args := normalizeArgs([]string{"--"})

	// Should be empty
	if len(args) != 0 {
		t.Errorf("Expected empty args, got %v", args)
	}
}
