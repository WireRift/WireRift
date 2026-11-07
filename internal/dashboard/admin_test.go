package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// adminFixture returns a dashboard handler with an admin account, a plain
// account and their token secrets.
func adminFixture(t *testing.T) (h http.Handler, adminTok, userTok string) {
	t.Helper()
	f := &auth.TokenFile{}
	yes := true
	adminTok, _, err := f.CreateToken(auth.CreateOptions{Account: "ops", Name: "ops", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1, Admin: &yes})
	if err != nil {
		t.Fatal(err)
	}
	userTok, _, err = f.CreateToken(auth.CreateOptions{Account: "alice", Name: "a", MaxTunnels: 3, MaxSessions: -1, RateLimit: -1})
	if err != nil {
		t.Fatal(err)
	}
	m := auth.NewManager("bootstrap")
	m.ApplyTokenFile(f)
	m.DisableBootstrapToken()
	srv := server.New(server.DefaultConfig(), nil)
	d := New(Config{Server: srv, AuthManager: m, Certs: func() []CertInfo {
		return []CertInfo{{Host: "a.example", Issuer: "Test CA", DaysLeft: 40}}
	}})
	return d.Handler(), adminTok, userTok
}

func get(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = "198.51.100.7:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminEndpointsRequireAdmin(t *testing.T) {
	h, adminTok, userTok := adminFixture(t)
	for _, path := range []string{"/api/admin/overview", "/api/admin/history", "/api/admin/accounts", "/api/admin/certs"} {
		if rec := get(h, "GET", path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token = %d, want 401", path, rec.Code)
		}
		if rec := get(h, "GET", path, userTok); rec.Code != http.StatusForbidden {
			t.Errorf("%s as plain account = %d, want 403", path, rec.Code)
		}
		if rec := get(h, "GET", path, adminTok); rec.Code != http.StatusOK {
			t.Errorf("%s as admin = %d, want 200", path, rec.Code)
		}
	}
	if rec := get(h, "POST", "/api/admin/sessions/x/kick", userTok); rec.Code != http.StatusForbidden {
		t.Errorf("kick as plain account = %d, want 403", rec.Code)
	}
}

func TestMeReportsRole(t *testing.T) {
	h, adminTok, userTok := adminFixture(t)
	var me map[string]any
	_ = json.Unmarshal(get(h, "GET", "/api/me", adminTok).Body.Bytes(), &me)
	if me["admin"] != true || me["account"] != "acct_ops" {
		t.Errorf("admin /api/me = %v", me)
	}
	me = nil
	_ = json.Unmarshal(get(h, "GET", "/api/me", userTok).Body.Bytes(), &me)
	if me["admin"] != false || me["account"] != "acct_alice" {
		t.Errorf("user /api/me = %v", me)
	}
}

func TestAdminAccountsAndCerts(t *testing.T) {
	h, adminTok, _ := adminFixture(t)
	var accts []map[string]any
	if err := json.Unmarshal(get(h, "GET", "/api/admin/accounts", adminTok).Body.Bytes(), &accts); err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, a := range accts {
		roles[a["id"].(string)] = a["admin"].(bool)
	}
	if roles["acct_ops"] != true || roles["acct_alice"] != false || len(accts) != 2 {
		t.Errorf("accounts = %v", accts)
	}
	var certs []CertInfo
	_ = json.Unmarshal(get(h, "GET", "/api/admin/certs", adminTok).Body.Bytes(), &certs)
	if len(certs) != 1 || certs[0].Host != "a.example" {
		t.Errorf("certs = %v", certs)
	}
}

func TestKickUnknownSessionAndBadPaths(t *testing.T) {
	h, adminTok, _ := adminFixture(t)
	if rec := get(h, "POST", "/api/admin/sessions/nope/kick", adminTok); rec.Code != http.StatusNotFound {
		t.Errorf("kick unknown = %d, want 404", rec.Code)
	}
	if rec := get(h, "GET", "/api/admin/sessions/nope/kick", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("kick via GET = %d, want 405", rec.Code)
	}
	if rec := get(h, "POST", "/api/admin/sessions/nope/other", adminTok); rec.Code != http.StatusNotFound {
		t.Errorf("unknown action = %d, want 404", rec.Code)
	}
	if rec := get(h, "POST", "/api/admin/overview", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST overview = %d, want 405", rec.Code)
	}
}

func TestUIContainsAdminTabsWithoutBackticks(t *testing.T) {
	d := New(Config{})
	rec := httptest.NewRecorder()
	d.serveIndex(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	for _, want := range []string{`data-tab="admin"`, `data-tab="activity"`, `id="panelAdmin"`, "/api/admin/overview"} {
		if !strings.Contains(body, want) {
			t.Errorf("index lacks %q", want)
		}
	}
}

func TestEventsEndpointScopesAndLimits(t *testing.T) {
	f := &auth.TokenFile{}
	adminTok, _, _ := f.CreateToken(auth.CreateOptions{Account: "ops", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1, Admin: func() *bool { b := true; return &b }()})
	userTok, _, _ := f.CreateToken(auth.CreateOptions{Account: "alice", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1})
	m := auth.NewManager("x")
	m.ApplyTokenFile(f)

	// A real server records "server started" with no account; start one briefly.
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.HTTPSAddr = "127.0.0.1:0", "127.0.0.1:0", ""
	cfg.TCPAddrRange = "42100-42110"
	live := server.New(cfg, nil)
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer live.Stop()
	h := New(Config{Server: live, AuthManager: m}).Handler()

	var all []server.Event
	rec := get(h, "GET", "/api/events?limit=1", adminTok)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &all) != nil || len(all) != 1 || all[0].Kind != "server" {
		t.Fatalf("admin events: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var own []server.Event
	rec = get(h, "GET", "/api/events?limit=999999", userTok) // out-of-range limit falls back to the default
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &own) != nil || len(own) != 0 {
		t.Fatalf("a plain account must not see server-wide events: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := get(h, "POST", "/api/events", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/events = %d", rec.Code)
	}
	if rec := get(h, "POST", "/api/me", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/me = %d", rec.Code)
	}
	if rec := get(h, "POST", "/api/admin/certs", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/admin/certs = %d", rec.Code)
	}
	if rec := get(h, "POST", "/api/admin/accounts", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/admin/accounts = %d", rec.Code)
	}
	rec = get(h, "GET", "/api/admin/certs", adminTok) // no provider configured: an empty list, not null
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("certs without provider = %q", rec.Body.String())
	}
	var hist []server.HistoryPoint
	rec = get(h, "GET", "/api/admin/history", adminTok)
	if json.Unmarshal(rec.Body.Bytes(), &hist) != nil || len(hist) < 1 {
		t.Errorf("history = %s", rec.Body.String())
	}
}

// A real client against a real server: scoping, usage, kick and events seen
// through the dashboard API.
func TestAdminViewWithLiveClients(t *testing.T) {
	f := &auth.TokenFile{}
	yes := true
	opsTok, _, _ := f.CreateToken(auth.CreateOptions{Account: "ops", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1, Admin: &yes})
	aliceTok, _, _ := f.CreateToken(auth.CreateOptions{Account: "alice", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1})
	bobTok, _, _ := f.CreateToken(auth.CreateOptions{Account: "bob", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1})
	m := auth.NewManager("x")
	m.ApplyTokenFile(f)

	cfg := server.DefaultConfig()
	cfg.Domain = "t.test"
	cfg.ControlAddr, cfg.HTTPAddr, cfg.HTTPSAddr = "127.0.0.1:0", "127.0.0.1:0", ""
	cfg.TCPAddrRange = "42300-42310"
	cfg.AuthManager = m
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	connect := func(tok string) *client.Client {
		cc := client.DefaultConfig()
		cc.ServerAddr, cc.Token, cc.Reconnect = srv.ControlAddr(), tok, false
		c := client.New(cc, nil)
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		if _, err := c.HTTP("127.0.0.1:9"); err != nil {
			t.Fatal(err)
		}
		return c
	}
	alice, bob := connect(aliceTok), connect(bobTok)
	defer alice.Close()
	defer bob.Close()

	h := New(Config{Server: srv, AuthManager: m}).Handler()
	count := func(path, tok string) int {
		var rows []map[string]any
		rec := get(h, "GET", path, tok)
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &rows) != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return len(rows)
	}
	if n := count("/api/tunnels", opsTok); n != 2 {
		t.Errorf("admin sees %d tunnels, want 2", n)
	}
	if n := count("/api/tunnels", aliceTok); n != 1 {
		t.Errorf("alice sees %d tunnels, want her 1", n)
	}
	if n := count("/api/sessions", aliceTok); n != 1 {
		t.Errorf("alice sees %d sessions, want 1", n)
	}
	if n := count("/api/sessions", opsTok); n != 2 {
		t.Errorf("admin sees %d sessions, want 2", n)
	}

	var accts []struct {
		ID       string `json:"id"`
		Sessions int    `json:"sessions"`
		Tunnels  int    `json:"tunnels"`
	}
	_ = json.Unmarshal(get(h, "GET", "/api/admin/accounts", opsTok).Body.Bytes(), &accts)
	usage := map[string][2]int{}
	for _, a := range accts {
		usage[a.ID] = [2]int{a.Sessions, a.Tunnels}
	}
	if usage["acct_alice"] != [2]int{1, 1} || usage["acct_bob"] != [2]int{1, 1} {
		t.Errorf("account usage = %v", usage)
	}

	var own []server.Event
	_ = json.Unmarshal(get(h, "GET", "/api/events", aliceTok).Body.Bytes(), &own)
	if len(own) == 0 {
		t.Fatal("alice should see her own connect/tunnel events")
	}
	for _, e := range own {
		if e.Account != "acct_alice" {
			t.Errorf("alice saw an event of %q", e.Account)
		}
	}

	sid := alice.SessionID()
	if rec := get(h, "POST", "/api/admin/sessions/"+sid+"/kick", opsTok); rec.Code != 200 {
		t.Fatalf("kick = %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for count("/api/sessions", opsTok) != 1 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := count("/api/sessions", opsTok); n != 1 {
		t.Errorf("after kick the admin sees %d sessions, want 1", n)
	}
	var ev []server.Event
	_ = json.Unmarshal(get(h, "GET", "/api/events?limit=50", opsTok).Body.Bytes(), &ev)
	kicked := false
	for _, e := range ev {
		if e.Kind == "admin" && strings.Contains(e.Message, "acct_ops") {
			kicked = true
		}
	}
	if !kicked {
		t.Error("the kick was not recorded as an event")
	}
}

// Any signed-in account (not only administrators) can read how to reach the
// server; a request without a token cannot.
func TestConnectInfoForAnyAccount(t *testing.T) {
	h, _, userTok := adminFixture(t)
	if rr := get(h, "GET", "/api/connect", ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("without a token: %d", rr.Code)
	}
	rr := get(h, "GET", "/api/connect", userTok)
	if rr.Code != http.StatusOK {
		t.Fatalf("plain account: %d %s", rr.Code, rr.Body)
	}
	var info server.ConnectInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.ServerArg == "" || info.TCPPortStart == 0 || len(info.Reserved) == 0 {
		t.Errorf("incomplete connect info: %+v", info)
	}
	if rr := get(h, "POST", "/api/connect", userTok); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rr.Code)
	}
}

// The page carries the Connect tab and the command builder.
func TestIndexHasConnectPage(t *testing.T) {
	h, _, _ := adminFixture(t)
	body := get(h, "GET", "/", "").Body.String()
	for _, want := range []string{`data-tab="connect"`, `id="panelConnect"`, "function cnBuild", "WIRERIFT_TOKEN"} {
		if !strings.Contains(body, want) {
			t.Errorf("index page lacks %q", want)
		}
	}
}
