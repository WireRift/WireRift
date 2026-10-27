package integration

// Stopping the server on purpose must tell connected clients so; they log it
// as a server decision instead of a dropped connection.

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestClientSeesAnIntentionalServerShutdown(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	authMgr := auth.NewManager()
	cfg.AuthManager = authMgr
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, slog.New(slog.NewTextHandler(logs, nil)))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = srv.Stop()
	waitFor(t, func() bool { return strings.Contains(logs.String(), "server closed the connection") }, "go-away log: "+logs.String())
	if !strings.Contains(logs.String(), "server is shutting down") {
		t.Fatalf("log lacks the reason:\n%s", logs.String())
	}
}
