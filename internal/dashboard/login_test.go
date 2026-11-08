package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
)

func loginFixture(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	h, _, _, adminTok, userTok, _ := tokenFixture(t)
	for acct, pw := range map[string]string{"ops": "ops password 123", "alice": "alice password 1"} {
		if rec := postJSON(h, "/api/admin/accounts/"+acct+"/password", adminTok, `{"password":"`+pw+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("set password %s: %d %s", acct, rec.Code, rec.Body)
		}
	}
	return h, adminTok, userTok
}

func login(h http.Handler, user, pass, ip string) (int, string) {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(b)))
	req.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var res struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res.Token
}

func TestPasswordLoginSessions(t *testing.T) {
	h, adminTok, _ := loginFixture(t)

	code, tok := login(h, "OPS", "ops password 123", "203.0.113.1")
	if code != http.StatusOK || !strings.HasPrefix(tok, "wrs_") {
		t.Fatalf("admin login: %d %q", code, tok)
	}
	if rec := get(h, "GET", "/api/admin/tokens", tok); rec.Code != http.StatusOK {
		t.Errorf("admin session cannot reach the admin API: %d", rec.Code)
	}
	_, utok := login(h, "alice", "alice password 1", "203.0.113.2")
	if rec := get(h, "GET", "/api/admin/tokens", utok); rec.Code != http.StatusForbidden {
		t.Errorf("a regular user's session reached the admin API: %d", rec.Code)
	}
	if rec := get(h, "GET", "/api/stats", utok); rec.Code != http.StatusOK {
		t.Errorf("regular session: %d", rec.Code)
	}

	// Logout ends the session; so does a new password.
	if rec := postJSON(h, "/api/logout", tok, ""); rec.Code != http.StatusOK {
		t.Errorf("logout: %d", rec.Code)
	}
	if rec := get(h, "GET", "/api/stats", tok); rec.Code != http.StatusUnauthorized {
		t.Errorf("session survived logout: %d", rec.Code)
	}
	if rec := postJSON(h, "/api/admin/accounts/alice/password", adminTok, `{"password":"another password 9"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := get(h, "GET", "/api/stats", utok); rec.Code != http.StatusUnauthorized {
		t.Errorf("session survived a password change: %d", rec.Code)
	}
	if c, _ := login(h, "alice", "alice password 1", "203.0.113.3"); c != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", c)
	}
	if c, _ := login(h, "alice", "another password 9", "203.0.113.3"); c != http.StatusOK {
		t.Errorf("new password: %d", c)
	}

	// A made-up session token is rejected.
	if rec := get(h, "GET", "/api/stats", "wrs_nonsense"); rec.Code != http.StatusUnauthorized {
		t.Errorf("fake session: %d", rec.Code)
	}
}

func TestPasswordLoginFailuresAndLockout(t *testing.T) {
	h, _, _ := loginFixture(t)
	for _, c := range [][2]string{{"ops", "wrong password!!"}, {"nobody", "whatever password"}} {
		if code, _ := login(h, c[0], c[1], "198.51.100.9"); code != http.StatusUnauthorized {
			t.Errorf("%v: %d", c, code)
		}
	}
	locked := false
	for i := 0; i < 30 && !locked; i++ {
		code, _ := login(h, "ops", "guess number "+string(rune('a'+i)), "198.51.100.10")
		locked = code == http.StatusTooManyRequests
	}
	if !locked {
		t.Error("repeated bad passwords never locked the address out")
	}
	if code, _ := login(h, "ops", "ops password 123", "198.51.100.10"); code != http.StatusTooManyRequests {
		t.Errorf("a locked address must stay locked: %d", code)
	}
	// Other methods and bodies.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/login", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET login: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad body: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/logout", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET logout: %d", rec.Code)
	}
}

func TestSetPasswordEndpointRules(t *testing.T) {
	h, adminTok, userTok := loginFixture(t)
	for _, c := range []struct {
		path, tok, body string
		want            int
	}{
		{"/api/admin/accounts/alice/password", userTok, `{"password":"hijack password 1"}`, http.StatusForbidden},
		{"/api/admin/accounts/alice/password", adminTok, `{"password":"short"}`, http.StatusBadRequest},
		{"/api/admin/accounts/ghost/password", adminTok, `{"password":"a long enough one"}`, http.StatusNotFound},
		{"/api/admin/accounts/alice/password", adminTok, `{`, http.StatusBadRequest},
		{"/api/admin/accounts/alice/other", adminTok, `{}`, http.StatusNotFound},
	} {
		if rec := postJSON(h, c.path, c.tok, c.body); rec.Code != c.want {
			t.Errorf("%s: %d, want %d", c.path, rec.Code, c.want)
		}
	}
	if rec := get(h, "GET", "/api/admin/accounts/alice/password", adminTok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
}

func TestLoginSessionStoreLimits(t *testing.T) {
	var s loginSessions
	first, _, _ := s.create("acct_a")
	for i := 0; i < maxLoginSessions; i++ {
		if _, _, err := s.create("acct_b"); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.m) > maxLoginSessions {
		t.Errorf("store grew to %d", len(s.m))
	}
	_ = first
	if _, ok := s.lookup("wrs_missing"); ok {
		t.Error("missing session found")
	}
}

var _ = auth.MinPasswordLength
