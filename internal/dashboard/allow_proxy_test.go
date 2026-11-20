package dashboard

// Regression test for the -dashboard-allow gate. The allow list decides who
// may reach the dashboard at all: CHANGELOG v1.27.0 promises that "everyone
// else gets 403 before the sign-in page", while direct loopback access (an
// SSH tunnel to the local port) always works.
//
// A same-host reverse proxy forwards visitors to the dashboard's local port,
// so the peer is loopback while the visitor is somewhere else. The forwarding
// header it sets marks the request as relayed rather than a direct local
// visit, so it must be judged by the allow list like any other remote caller
// -- the same rule the server's /metrics gate applies (see
// internal/server/observability.go metricsAllowed). Treating every loopback
// peer as local voided the allow list behind such a proxy.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDashboardAllowListRejectsForwardedVisitor(t *testing.T) {
	d := New(Config{Allow: []string{"203.0.113.7"}})
	h := d.Handler()

	for _, header := range []struct {
		name  string
		value string
	}{
		{"X-Forwarded-For", "198.51.100.9"},
		{"Forwarded", "for=198.51.100.9"},
		{"X-Real-Ip", "198.51.100.9"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:5000" // the same-host proxy's socket
		req.Header.Set(header.name, header.value)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s via a same-host reverse proxy: %d, want %d",
				header.name, rec.Code, http.StatusForbidden)
		}
	}

	// Control: the SSH tunnel to the local port carries no forwarding header
	// and keeps working.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("SSH tunnel to the local port: %d, want %d", rec.Code, http.StatusOK)
	}
}
