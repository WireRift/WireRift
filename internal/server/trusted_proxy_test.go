package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func trustedProxyServer(t *testing.T, cidrs ...string) *Server {
	t.Helper()
	prefixes, err := parseTrustedProxyCIDRs(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{trustedProxyNets: prefixes, pinSecret: []byte("test-secret")}
}

func TestClientIPTrustedProxyBoundary(t *testing.T) {
	overlong := make([]string, maxForwardedForHops+1)
	for i := range overlong {
		overlong[i] = fmt.Sprintf("198.51.100.%d", i+1)
	}

	tests := []struct {
		name   string
		cidrs  []string
		remote string
		xff    string
		want   string
	}{
		{
			name:  "direct visitor cannot spoof",
			cidrs: []string{"10.0.0.0/8"}, remote: "203.0.113.7:5000",
			xff: "198.51.100.9", want: "203.0.113.7",
		},
		{
			name:  "trusted proxy supplies visitor",
			cidrs: []string{"10.0.0.0/8"}, remote: "10.0.0.5:5000",
			xff: "198.51.100.9", want: "198.51.100.9",
		},
		{
			name:  "right to left stops at first untrusted hop",
			cidrs: []string{"10.0.0.0/8", "192.168.0.0/16"}, remote: "10.0.0.5:5000",
			xff: "203.0.113.9, 198.51.100.7, 192.168.1.8", want: "198.51.100.7",
		},
		{
			name:  "malformed chain fails closed",
			cidrs: []string{"10.0.0.0/8"}, remote: "10.0.0.5:5000",
			xff: "198.51.100.9, unknown", want: "10.0.0.5",
		},
		{
			name:  "oversized chain fails closed",
			cidrs: []string{"10.0.0.0/8"}, remote: "10.0.0.5:5000",
			xff: strings.Join(overlong, ","), want: "10.0.0.5",
		},
		{
			name:  "IPv6 proxy and visitor",
			cidrs: []string{"2001:db8:1234::/48"}, remote: "[2001:db8:1234::5]:5000",
			xff: "2001:db8:abcd::9", want: "2001:db8:abcd::9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := trustedProxyServer(t, tt.cidrs...)
			r := httptest.NewRequest("GET", "http://app.example.test/", nil)
			r.RemoteAddr = tt.remote
			r.Header.Set("X-Forwarded-For", tt.xff)
			if got := s.clientIP(r); got != tt.want {
				t.Fatalf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTrustedProxySerializationEmitsOnlyResolvedClient(t *testing.T) {
	s := trustedProxyServer(t, "10.0.0.0/8", "192.168.0.0/16")
	r := httptest.NewRequest("GET", "http://app.example.test/", nil)
	r.RemoteAddr = "10.0.0.5:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7, 192.168.1.8")

	data, err := s.serializeRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(data)
	if !strings.Contains(serialized, "X-Forwarded-For: 198.51.100.7\r\n") {
		t.Fatalf("resolved client missing:\n%s", serialized)
	}
	if strings.Contains(serialized, "203.0.113.9") || strings.Contains(serialized, "192.168.1.8") {
		t.Fatalf("untrusted or internal chain leaked:\n%s", serialized)
	}
}

func TestTrustedProxyCIDRValidation(t *testing.T) {
	for _, cidrs := range [][]string{
		{""},
		{"10.0.0.1"},
		{"not-a-cidr"},
		{"10.0.0.0/8", "bad"},
	} {
		if _, err := parseTrustedProxyCIDRs(cidrs); err == nil {
			t.Errorf("parseTrustedProxyCIDRs(%q) succeeded, want error", cidrs)
		}
	}
	prefixes, err := parseTrustedProxyCIDRs([]string{"10.1.2.3/8", "2001:db8:1234::/48"})
	if err != nil || len(prefixes) != 2 || prefixes[0].String() != "10.0.0.0/8" {
		t.Fatalf("valid CIDRs: prefixes=%v err=%v", prefixes, err)
	}
}

func TestInvalidTrustedProxyCIDRStopsBeforeListening(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.TrustedProxyCIDRs = []string{"10.0.0.1"}
	s := New(cfg, nil)
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "invalid trusted proxy CIDRs") {
		t.Fatalf("Start() error = %v, want invalid trusted proxy CIDRs", err)
	}
	if s.controlListener != nil || s.httpListener != nil {
		t.Fatal("invalid trusted proxy config opened listeners")
	}
}

func TestPINGuardUsesResolvedVisitorBehindTrustedProxy(t *testing.T) {
	s := trustedProxyServer(t, "10.0.0.0/8")
	for i := 0; i < pinMaxFailures; i++ {
		r := httptest.NewRequest("GET", "http://app.example.test/", nil)
		r.RemoteAddr = "10.0.0.5:5000"
		r.Header.Set("X-Forwarded-For", "198.51.100.1")
		r.Header.Set("X-WireRift-PIN", "wrong")
		s.checkPIN(httptest.NewRecorder(), r, "right", "app")
	}
	if !s.pinGuard.locked("app|198.51.100.1") {
		t.Fatal("resolved visitor was not locked")
	}
	if s.pinGuard.locked("app|198.51.100.2") {
		t.Fatal("different visitor sharing the same proxy was locked")
	}
}
