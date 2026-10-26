package integration

// A token of a file account must only see its own tunnels, sessions, captured
// requests and counts on the dashboard API; the bootstrap token sees all.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/dashboard"
	"github.com/wirerift/wirerift/internal/server"
)

func TestDashboardShowsOnlyTheCallersAccount(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer local.Close()
	localAddr := strings.TrimPrefix(local.URL, "http://")

	tf := &auth.TokenFile{}
	secrets := map[string]string{}
	for _, name := range []string{"alice", "bob"} {
		s, _, err := tf.CreateToken(auth.CreateOptions{Account: name, Name: "t"})
		if err != nil {
			t.Fatal(err)
		}
		secrets[name] = s
	}
	authMgr := auth.NewManager()
	authMgr.ApplyTokenFile(tf)

	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	logIDs := map[string]string{}
	for name, secret := range secrets {
		cc := client.DefaultConfig()
		cc.ServerAddr = srv.ControlAddr()
		cc.Token = secret
		cc.Reconnect = false
		c := client.New(cc, nil)
		if err := c.Connect(); err != nil {
			t.Fatalf("%s connect: %v", name, err)
		}
		defer c.Close()
		tun, err := c.HTTP(localAddr, client.WithSubdomain("scope-"+name), client.WithInspect())
		if err != nil {
			t.Fatalf("%s tunnel: %v", name, err)
		}
		req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/x", nil)
		req.Host = "scope-" + name + "." + cfg.Domain
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		waitFor(t, func() bool {
			for _, l := range srv.GetRequestLogs(tun.ID, 10) {
				logIDs[name] = l.ID
				return true
			}
			return false
		}, name+" request log")
	}

	handler := dashboard.New(dashboard.Config{Server: srv, AuthManager: authMgr}).Handler()
	get := func(token, path string, out any) int {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if out != nil && rec.Code == 200 {
			if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return rec.Code
	}

	var tunnels []struct {
		ID        string `json:"id"`
		AccountID string `json:"account_id"`
	}
	var sessions []struct {
		AccountID string `json:"account_id"`
	}
	var logs []struct {
		ID string `json:"id"`
	}
	var stats map[string]any

	get(secrets["alice"], "/api/tunnels", &tunnels)
	get(secrets["alice"], "/api/sessions", &sessions)
	get(secrets["alice"], "/api/requests", &logs)
	get(secrets["alice"], "/api/stats", &stats)
	if len(tunnels) != 1 || tunnels[0].AccountID != "acct_alice" {
		t.Errorf("alice sees tunnels %+v, want only her own", tunnels)
	}
	if len(sessions) != 1 || sessions[0].AccountID != "acct_alice" {
		t.Errorf("alice sees sessions %+v, want only her own", sessions)
	}
	if len(logs) != 1 || logs[0].ID != logIDs["alice"] {
		t.Errorf("alice sees request logs %+v, want only %s", logs, logIDs["alice"])
	}
	if stats["active_tunnels"] != float64(1) || stats["active_sessions"] != float64(1) {
		t.Errorf("alice stats = %v, want 1 tunnel and 1 session", stats)
	}
	if _, leaked := stats["bytes_in"]; leaked {
		t.Error("server-wide traffic totals must not reach a non-admin account")
	}

	// Alice cannot replay Bob's request; the admin can.
	post := func(token, id string) int {
		req := httptest.NewRequest("POST", "/api/requests/"+id+"/replay", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(secrets["alice"], logIDs["bob"]); code != http.StatusBadRequest {
		t.Errorf("alice replaying bob's request: status %d, want 400", code)
	}
	if code := post(secrets["alice"], logIDs["alice"]); code != http.StatusOK {
		t.Errorf("alice replaying her own request: status %d, want 200", code)
	}
	if code := post(authMgr.DevToken(), logIDs["bob"]); code != http.StatusOK {
		t.Errorf("admin replaying bob's request: status %d, want 200", code)
	}

	tunnels, sessions, logs = nil, nil, nil
	get(authMgr.DevToken(), "/api/tunnels", &tunnels)
	get(authMgr.DevToken(), "/api/sessions", &sessions)
	if len(tunnels) != 2 || len(sessions) != 2 {
		t.Errorf("admin sees %d tunnels and %d sessions, want 2 and 2", len(tunnels), len(sessions))
	}
}
