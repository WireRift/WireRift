package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAllowList(t *testing.T) {
	nets, err := ParseAllowList([]string{" 203.0.113.7 ", "198.51.100.0/24", "2001:db8::1", "2001:db8:ffff::/48", ""})
	if err != nil || len(nets) != 4 {
		t.Fatalf("nets=%v err=%v", nets, err)
	}
	for _, bad := range []string{"nonsense", "300.1.1.1", "10.0.0.0/99"} {
		if _, err := ParseAllowList([]string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestDashboardAllowList(t *testing.T) {
	d := New(Config{Allow: []string{"203.0.113.7", "198.51.100.0/24", "2001:db8::/32"}})
	h := d.Handler()
	for _, c := range []struct {
		remote string
		want   int
	}{
		{"203.0.113.7:5555", http.StatusOK}, // listed address
		{"198.51.100.200:1", http.StatusOK}, // inside a listed range
		{"[2001:db8::9]:1", http.StatusOK},  // IPv6 range
		{"203.0.113.8:5555", http.StatusForbidden},
		{"[2001:db9::1]:1", http.StatusForbidden},
		{"127.0.0.1:40000", http.StatusOK},    // SSH tunnel to the local port
		{"127.0.0.1:0", http.StatusForbidden}, // relayed by the edge: judged by the visitor's address
		{"not an address", http.StatusForbidden},
		{"[::1]:0", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: %d, want %d", c.remote, rec.Code, c.want)
		}
	}
	// Edge-relayed requests with a listed visitor address pass.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:0"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("relayed listed visitor: %d", rec.Code)
	}
	// An empty list lets everyone reach the sign-in page.
	open := New(Config{}).Handler()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1"
	rec = httptest.NewRecorder()
	open.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("no allow list: %d", rec.Code)
	}
}
