//go:build !windows

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

// SIGHUP reloads the token file at once, even before the next poll.
func TestWatchTokenFileReloadsOnSIGHUP(t *testing.T) {
	// A SIGHUP that lands before the watcher has registered would kill the test
	// process (default action); keep it registered here for the whole test.
	guard := make(chan os.Signal, 16)
	signal.Notify(guard, syscall.SIGHUP)
	defer signal.Stop(guard)

	file := filepath.Join(t.TempDir(), "tokens.json")
	tf := &auth.TokenFile{}
	if err := tf.Save(file); err != nil {
		t.Fatal(err)
	}
	srv := &fakeCloser{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchTokenFile(ctx, auth.NewManager(), srv, file, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))

	for i := 0; i < 300 && srv.calls.Load() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP) // retried until the watcher has registered
	}
	if srv.calls.Load() == 0 {
		t.Fatal("SIGHUP did not trigger a reload")
	}
}
