package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

type fakeCloser struct{ calls atomic.Int32 }

func (f *fakeCloser) CloseRevokedSessions() int { f.calls.Add(1); return 0 }

func TestWatchTokenFileReloadsOnChange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tokens.json")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := auth.NewManager()

	tf := &auth.TokenFile{}
	first, _, err := tf.CreateToken(auth.CreateOptions{Account: "acme", Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tf.Save(file); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.LoadTokenFile(file); err != nil { // what the server does at startup
		t.Fatal(err)
	}

	srv := &fakeCloser{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchTokenFile(ctx, mgr, srv, file, 10*time.Millisecond, logger)

	waitUntil := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; i < 300; i++ {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	valid := func(secret string) bool { _, _, err := mgr.ValidateToken(secret); return err == nil }

	if !valid(first) {
		t.Fatal("the startup load did not register the token")
	}

	time.Sleep(100 * time.Millisecond) // let the watcher record the file's current version

	// A new token appears without a restart; a revoked one stops working.
	second, rec, err := tf.CreateToken(auth.CreateOptions{Account: "acme", Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tf.Revoke(rec.ID); err != nil {
		t.Fatal(err)
	}
	third, _, _ := tf.CreateToken(auth.CreateOptions{Account: "acme", Name: "c"})
	if err := tf.Save(file); err != nil {
		t.Fatal(err)
	}
	waitUntil("the edited file to be reloaded", func() bool { return valid(third) })
	if valid(second) {
		t.Error("a revoked token still authenticates after the reload")
	}
	if srv.calls.Load() == 0 {
		t.Error("sessions were not re-checked after the reload")
	}

	// A broken file leaves the loaded tokens in force.
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !valid(third) {
		t.Error("a corrupt token file wiped the tokens in force")
	}

}
