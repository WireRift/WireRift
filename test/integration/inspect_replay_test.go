package integration

// Regression test for inspector replay fidelity: logRequest captured only
// r.URL.Path, so ReplayRequest rebuilt the captured request WITHOUT its query
// string and the local app silently received a different request (/echo
// instead of /echo?msg=hello). Capture now stores RawQuery (RequestLog.Query)
// and replay restores it, so a replay reaches the local app exactly as the
// original did.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

func TestInspectReplayPreservesQuery(t *testing.T) {
	var mu sync.Mutex
	var seenQueries []string
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenQueries = append(seenQueries, r.URL.RawQuery)
		mu.Unlock()
		fmt.Fprintf(w, "query:%s", r.URL.RawQuery)
	}))
	defer local.Close()

	authMgr := auth.NewManager()
	srvCfg := server.DefaultConfig()
	srvCfg.ControlAddr = "127.0.0.1:0"
	srvCfg.HTTPAddr = "127.0.0.1:0"
	srvCfg.AuthManager = authMgr

	srv := server.New(srvCfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Server start: %v", err)
	}
	defer srv.Stop()

	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = srv.ControlAddr()
	clientCfg.Token = authMgr.DevToken()
	clientCfg.Reconnect = false

	c := client.New(clientCfg, nil)
	if err := c.Connect(); err != nil {
		t.Fatalf("Client connect: %v", err)
	}
	defer c.Close()

	tunnel, err := c.HTTP(strings.TrimPrefix(local.URL, "http://"),
		client.WithSubdomain("qreplay"), client.WithInspect())
	if err != nil {
		t.Fatalf("Create HTTP tunnel: %v", err)
	}

	// Original visitor request WITH a query string.
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/echo", srv.HTTPAddr()), nil)
	req.Host = fmt.Sprintf("qreplay.%s", srvCfg.Domain)
	req.URL.RawQuery = "msg=hello"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Edge HTTP request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "query:msg=hello" {
		t.Fatalf("Original request: status=%d body=%q", resp.StatusCode, body)
	}

	// Wait for the capture.
	var logID string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && logID == "" {
		for _, l := range srv.GetRequestLogs(tunnel.ID, 10) {
			if l.Method == "GET" && l.Path == "/echo" {
				logID = l.ID
			}
		}
		if logID == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if logID == "" {
		t.Fatal("Captured request log not found")
	}

	// Replay it and require the local app to see the same query.
	replay, err := srv.ReplayRequest(logID)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replay.StatusCode != 200 {
		t.Fatalf("Replay status = %d, want 200", replay.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenQueries) < 2 {
		t.Fatalf("Replayed request never reached the local app (saw %d requests)", len(seenQueries))
	}
	if seenQueries[1] != "msg=hello" {
		t.Fatalf("Replayed request lost the query string: local app saw RawQuery %q, want %q", seenQueries[1], "msg=hello")
	}
}
