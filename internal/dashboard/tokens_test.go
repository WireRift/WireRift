package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/server"
)

// tokenFixture is a dashboard over a real token file with one administrator
// and one plain account. changes counts OnTokensChanged calls; the manager is
// reloaded from the file on each change, as the server command does.
func tokenFixture(t *testing.T) (h http.Handler, m *auth.Manager, path, adminTok, userTok string, changes *int) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "tokens.json")
	f := &auth.TokenFile{}
	yes := true
	var err error
	adminTok, _, err = f.CreateToken(auth.CreateOptions{Account: "ops", Name: "ops", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1, Admin: &yes})
	if err != nil {
		t.Fatal(err)
	}
	userTok, _, err = f.CreateToken(auth.CreateOptions{Account: "alice", Name: "a", MaxTunnels: 3, MaxSessions: -1, RateLimit: -1})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	m = auth.NewManager("bootstrap")
	if _, err := m.LoadTokenFile(path); err != nil {
		t.Fatal(err)
	}
	m.DisableBootstrapToken()
	changes = new(int)
	d := New(Config{
		Server: server.New(server.DefaultConfig(), nil), AuthManager: m, TokenFile: path,
		OnTokensChanged: func() { *changes++; _, _ = m.LoadTokenFile(path) },
	})
	return d.Handler(), m, path, adminTok, userTok, changes
}

func postJSON(h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "198.51.100.7:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTokenEndpointsAreAdminOnly(t *testing.T) {
	h, _, _, adminTok, userTok, _ := tokenFixture(t)
	if rec := get(h, "GET", "/api/admin/tokens", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := get(h, "GET", "/api/admin/tokens", userTok); rec.Code != http.StatusForbidden {
		t.Errorf("plain account list: %d", rec.Code)
	}
	if rec := postJSON(h, "/api/admin/tokens", userTok, `{"account":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("plain account create: %d", rec.Code)
	}
	if rec := postJSON(h, "/api/admin/tokens/tok_x/revoke", userTok, ""); rec.Code != http.StatusForbidden {
		t.Errorf("plain account revoke: %d", rec.Code)
	}
	if rec := get(h, "GET", "/api/admin/tokens", adminTok); rec.Code != http.StatusOK {
		t.Errorf("admin list: %d", rec.Code)
	}
}

// Every create gives a separate secret that works at once; the list never
// shows a secret; revoking one token leaves the others working.
func TestCreateListAndRevokeTokens(t *testing.T) {
	h, m, path, adminTok, userTok, changes := tokenFixture(t)

	created := func(body string) (id, secret string) {
		t.Helper()
		rec := postJSON(h, "/api/admin/tokens", adminTok, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", body, rec.Code, rec.Body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Error("a response carrying a secret must not be cached")
		}
		var res struct{ ID, Secret string }
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res.ID, res.Secret
	}
	id1, sec1 := created(`{"account":"bob","name":"laptop","max_tunnels":2,"expires":"30d"}`)
	id2, sec2 := created(`{"account":"bob","name":"phone"}`)
	if id1 == id2 || sec1 == sec2 {
		t.Fatal("two creates must give two different tokens")
	}
	if *changes != 2 {
		t.Errorf("server told %d times, want 2", *changes)
	}
	for _, sec := range []string{sec1, sec2} {
		if _, a, err := m.ValidateToken(sec); err != nil || a.ID != "acct_bob" {
			t.Errorf("new token not valid at once: %v", err)
		}
	}

	body := get(h, "GET", "/api/admin/tokens", adminTok).Body.String()
	if strings.Contains(body, sec1) || strings.Contains(body, sec2) || strings.Contains(body, "hash") {
		t.Error("the list leaks a secret or a digest")
	}
	var rows []tokenRow
	if err := json.Unmarshal([]byte(body), &rows); err != nil || len(rows) != 4 {
		t.Fatalf("want 4 tokens, got %d (%v)", len(rows), err)
	}

	if rec := postJSON(h, "/api/admin/tokens/"+id1+"/revoke", adminTok, ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if _, _, err := m.ValidateToken(sec1); err == nil {
		t.Error("a revoked token still works")
	}
	if _, _, err := m.ValidateToken(sec2); err != nil {
		t.Errorf("the other token of the account must keep working: %v", err)
	}
	if _, _, err := m.ValidateToken(userTok); err != nil {
		t.Errorf("an unrelated token broke: %v", err)
	}
	f, _ := auth.LoadTokenFile(path)
	for _, tok := range f.Tokens {
		if tok.ID == id1 && !tok.Revoked {
			t.Error("revocation not saved")
		}
	}
	if rec := postJSON(h, "/api/admin/tokens/tok_nope/revoke", adminTok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown token: %d", rec.Code)
	}
}

func TestCreateTokenValidation(t *testing.T) {
	h, _, _, adminTok, _, changes := tokenFixture(t)
	for name, body := range map[string]string{
		"not json":        `{`,
		"no account":      `{"name":"x"}`,
		"bad account":     `{"account":"no spaces!"}`,
		"negative limit":  `{"account":"zed","max_tunnels":-5}`,
		"bad lifetime":    `{"account":"zed","expires":"soon"}`,
		"oversized input": `{"account":"` + strings.Repeat("a", 5000) + `"}`,
	} {
		if rec := postJSON(h, "/api/admin/tokens", adminTok, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400 (%s)", name, rec.Code, rec.Body)
		}
	}
	if *changes != 0 {
		t.Errorf("a refused request changed the tokens (%d)", *changes)
	}
	if rec := get(h, "DELETE", "/api/admin/tokens", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: %d", rec.Code)
	}
	if rec := get(h, "GET", "/api/admin/tokens/tok_x/revoke", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET revoke: %d", rec.Code)
	}
	if rec := postJSON(h, "/api/admin/tokens/tok_x/other", adminTok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown action: %d", rec.Code)
	}
}

func TestCreateTokenCanMakeAdministrators(t *testing.T) {
	h, m, _, adminTok, _, _ := tokenFixture(t)
	rec := postJSON(h, "/api/admin/tokens", adminTok, `{"account":"deputy","admin":true}`)
	var res struct{ Secret string }
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if _, a, err := m.ValidateToken(res.Secret); err != nil || !a.IsAdmin() {
		t.Errorf("the new account should be an administrator (err %v)", err)
	}
	if rec := get(h, "GET", "/api/admin/tokens", res.Secret); rec.Code != http.StatusOK {
		t.Errorf("the new administrator cannot list tokens: %d", rec.Code)
	}
}

func TestTokenManagementOffWithoutFile(t *testing.T) {
	h, adminTok, _ := adminFixture(t) // no TokenFile configured
	for _, rec := range []*httptest.ResponseRecorder{
		get(h, "GET", "/api/admin/tokens", adminTok),
		postJSON(h, "/api/admin/tokens", adminTok, `{"account":"x"}`),
		postJSON(h, "/api/admin/tokens/tok_x/revoke", adminTok, ""),
	} {
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("want 501, got %d", rec.Code)
		}
	}
}

func TestTokenStatuses(t *testing.T) {
	h, _, path, adminTok, _, _ := tokenFixture(t)
	f, _ := auth.LoadTokenFile(path)
	for i := range f.Accounts {
		if f.Accounts[i].Name == "alice" {
			f.Accounts[i].Active = false
		}
	}
	past := f.Tokens[0].CreatedAt.Add(-1)
	f.Tokens[0].ExpiresAt = &past
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	var rows []tokenRow
	_ = json.Unmarshal(get(h, "GET", "/api/admin/tokens", adminTok).Body.Bytes(), &rows)
	got := map[string]string{}
	for _, r := range rows {
		got[r.Account] = r.Status
	}
	if got["ops"] != "expired" || got["alice"] != "account disabled" {
		t.Errorf("statuses: %v", got)
	}
}

func TestIndexHasTokenManagement(t *testing.T) {
	h, _, _ := adminFixture(t)
	body := get(h, "GET", "/", "").Body.String()
	for _, want := range []string{`id="tbodyTokens"`, "function createToken", "data-revoke"} {
		if !strings.Contains(body, want) {
			t.Errorf("index page lacks %q", want)
		}
	}
}
