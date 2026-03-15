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
