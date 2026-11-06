package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRejectsUnreadableDashboardTLSBeforeCoreStart(t *testing.T) {
	stateDir := t.TempDir()
	missingCert := filepath.Join(stateDir, "missing-dashboard.crt")
	missingKey := filepath.Join(stateDir, "missing-dashboard.key")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := run(ctx, []string{
		"-control", "127.0.0.1:0",
		"-http", "127.0.0.1:0",
		"-dashboard-bind", "127.0.0.1",
		"-dashboard-port", "0",
		"-tcp-ports", "30000-30010",
		"-cert-dir", stateDir,
		"-token", "lifecycle-proof-token",
		"-dashboard-tls-cert", missingCert,
		"-dashboard-tls-key", missingKey,
	})
	if err == nil || !strings.Contains(err.Error(), "load dashboard TLS") {
		t.Fatalf("run error = %v, want dashboard TLS validation before startup", err)
	}
}

func TestAwaitRuntimeEndPreservesFatalCause(t *testing.T) {
	t.Run("server error wins cancellation race", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		serverErrors := make(chan error, 1)
		dashboardErrors := make(chan error, 1)
		serverErrors <- errors.New("edge failed")
		cancel()
		err := awaitRuntimeEnd(ctx, cancel, serverErrors, dashboardErrors)
		if err == nil || !strings.Contains(err.Error(), "server runtime failure: edge failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("dashboard error cancels runtime", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverErrors := make(chan error, 1)
		dashboardErrors := make(chan error, 1)
		dashboardErrors <- errors.New("dashboard failed")
		err := awaitRuntimeEnd(ctx, cancel, serverErrors, dashboardErrors)
		if err == nil || !strings.Contains(err.Error(), "dashboard runtime failure: dashboard failed") {
			t.Fatalf("error = %v", err)
		}
		if ctx.Err() == nil {
			t.Fatal("dashboard failure did not cancel runtime")
		}
	})

	t.Run("operator cancellation is clean", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		serverErrors := make(chan error, 1)
		dashboardErrors := make(chan error, 1)
		cancel()
		if err := awaitRuntimeEnd(ctx, cancel, serverErrors, dashboardErrors); err != nil {
			t.Fatalf("operator cancellation: %v", err)
		}
	})
}

func TestServeDashboardReportsUnexpectedListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: time.Second,
	}
	if err := serveDashboard(server, listener, false); err == nil {
		t.Fatal("closed dashboard listener was treated as a clean shutdown")
	}
}
