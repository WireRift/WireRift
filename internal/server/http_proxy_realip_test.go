package server

// Regression tests for X-Real-IP emission in the tunneled request.
//
// The edge is the trust boundary for the client address: it re-emits
// X-Forwarded-For/Proto/Host itself and drops the visitor's copies, because a
// direct visitor can supply any of them and would otherwise choose the
// address the tunneled application sees. X-Real-IP is the other widely used
// convention for the same value (nginx $http_x_real_ip, Express req.ip behind
// a proxy) and SPEC §8.2 lists it among the headers the server adds, but it
// was neither emitted nor stripped: a visitor-supplied X-Real-Ip reached the
// local application verbatim. See test/integration/x_real_ip_test.go for the
// end-to-end case.

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSerializeRequestEmitsTrustedRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://app.example.com/", nil)
	req.RemoteAddr = "203.0.113.7:5000"
	req.Host = "app.example.com"
	// The visitor tries to choose the client address the local app reads.
	req.Header.Set("X-Real-Ip", "198.51.100.99")
	req.Header.Set("X-Forwarded-For", "198.51.100.88")
	// Control: an ordinary visitor header must still be forwarded verbatim.
	req.Header.Set("X-Custom-Probe", "keep-me")

	data, err := SerializeRequest(req)
	if err != nil {
		t.Fatalf("SerializeRequest failed: %v", err)
	}
	s := string(data)

	if got := strings.Count(s, "\r\nX-Real-IP: "); got != 1 {
		t.Fatalf("X-Real-IP header count = %d, want exactly 1:\n%s", got, s)
	}
	if !strings.Contains(s, "\r\nX-Real-IP: 203.0.113.7\r\n") {
		t.Errorf("serialized request missing the real client IP:\n%s", s)
	}
	if strings.Contains(s, "198.51.100.99") {
		t.Errorf("visitor-supplied X-Real-Ip leaked to the backend:\n%s", s)
	}
	if !strings.Contains(s, "\r\nX-Custom-Probe: keep-me\r\n") {
		t.Errorf("ordinary visitor header was dropped:\n%s", s)
	}
}

func TestSerializeRequestRealIPFollowsTrustedProxy(t *testing.T) {
	s := trustedProxyServer(t, "10.0.0.0/8")
	r := httptest.NewRequest("GET", "http://app.example.test/", nil)
	r.RemoteAddr = "10.0.0.5:5000"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")

	data, err := s.serializeRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(data)
	if !strings.Contains(serialized, "\r\nX-Real-IP: 198.51.100.9\r\n") {
		t.Fatalf("X-Real-IP does not carry the resolved client IP:\n%s", serialized)
	}
}
