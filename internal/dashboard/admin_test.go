package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
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
