package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

// tokenReloadInterval is how often the token file is checked for changes.
const tokenReloadInterval = 5 * time.Second

// sessionCloser is the part of the server that tokenReloader needs.
type sessionCloser interface {
	CloseRevokedSessions() int
}

// watchTokenFile reloads path into mgr whenever the file changes (checked every
// interval) or the process receives SIGHUP, then closes the sessions whose
// token is gone. A file that fails to parse is logged and the tokens already
// loaded stay in force. It returns when ctx ends.
func watchTokenFile(ctx context.Context, mgr *auth.Manager, srv sessionCloser, path string, interval time.Duration, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	last := fileStamp(path)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		force := false
		select {
		case <-ctx.Done():
			return
		case <-hup:
			force = true
		case <-ticker.C:
		}
		if cur := fileStamp(path); force || cur != last {
			last = cur
			reloadTokens(mgr, srv, path, logger)
		}
	}
}

type stamp struct {
	mod  time.Time
	size int64
}

// fileStamp identifies a version of the file; a missing file has the zero stamp.
func fileStamp(path string) stamp {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}
	}
	return stamp{fi.ModTime(), fi.Size()}
}

func reloadTokens(mgr *auth.Manager, srv sessionCloser, path string, logger *slog.Logger) {
	n, err := mgr.LoadTokenFile(path)
	if err != nil {
		logger.Error("token file not reloaded, keeping the previous tokens", "file", path, "error", err)
		return
	}
	closed := srv.CloseRevokedSessions()
	logger.Info("reloaded tokens", "count", n, "file", path, "sessions_closed", closed)
}
