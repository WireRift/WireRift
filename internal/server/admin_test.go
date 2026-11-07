package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestEventLogKeepsNewestAndFilters(t *testing.T) {
	s := New(DefaultConfig(), nil)
	for i := 0; i < maxEvents+25; i++ {
		acct := "a"
		if i%2 == 0 {
			acct = "b"
		}
		s.recordEvent("info", "test", acct, "", "", "event "+strconv.Itoa(i))
	}
	all := s.Events(0, "")
	if len(all) != maxEvents {
		t.Fatalf("kept %d events, want %d", len(all), maxEvents)
	}
	if all[0].Message != "event "+strconv.Itoa(maxEvents+24) {
		t.Errorf("newest first expected, got %q", all[0].Message)
	}
	if all[0].ID <= all[1].ID {
		t.Errorf("IDs must increase over time: %d, %d", all[0].ID, all[1].ID)
	}
	for _, e := range s.Events(10, "a") {
		if e.Account != "a" {
			t.Fatalf("filter leaked %q", e.Account)
		}
	}
	if got := len(s.Events(5, "")); got != 5 {
		t.Errorf("limit 5 returned %d", got)
	}
}

func TestHistorySamplingAndRing(t *testing.T) {
	s := New(DefaultConfig(), nil)
	s.httpStatus[1].Add(3)
	s.httpStatus[3].Add(1)
	s.bytesIn.Store(1000)
	for i := 0; i < maxHistory+5; i++ {
		s.history.add(s.sampleHistory())
	}
	h := s.History()
	if len(h) != maxHistory {
		t.Fatalf("history length %d, want %d", len(h), maxHistory)
	}
	last := h[len(h)-1]
	if last.Requests != 4 || last.Err4xx != 1 || last.BytesIn != 1000 || last.Goroutines < 1 || last.HeapMB <= 0 {
		t.Errorf("sample = %+v", last)
	}
}

func TestAdminOverviewReflectsState(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Version = "v9.9.9"
	cfg.EdgeRatePerIP = 250
	s := New(cfg, nil)
	s.startTime = time.Now().Add(-time.Minute)
	s.ready.Store(true)
	s.sessions.Store("s1", &Session{ID: "s1", AccountID: "acct_a"})
	s.tunnels.Store("web", &Tunnel{ID: "t1", AccountID: "acct_a", Type: "http"})
	s.held.Store("gone", heldName{accountID: "acct_a", until: time.Now().Add(time.Minute)})
	s.held.Store("old", heldName{accountID: "acct_a", until: time.Now().Add(-time.Minute)})
	s.httpStatus[1].Add(8)
	s.httpStatus[4].Add(2)
	for i := 0; i < 10; i++ {
		s.observeHTTPRequest(200, 20*time.Millisecond)
	}
	o := s.AdminOverview()
	if o.Version != "v9.9.9" || !o.Ready || o.Sessions != 1 || o.HTTPTunnels != 1 || o.EdgeRate != 250 || o.EdgeBurst != 50 {
		t.Errorf("overview = %+v", o)
	}
	if len(o.Held) != 1 || o.Held[0].Subdomain != "gone" {
		t.Errorf("held = %+v (expired must be hidden)", o.Held)
	}
	if len(o.Accounts) != 1 || o.Accounts[0].Sessions != 1 || o.Accounts[0].Tunnels != 1 {
		t.Errorf("accounts = %+v", o.Accounts)
	}
	if o.Status["2xx"] != 18 && o.Status["2xx"] != 8 {
		t.Errorf("status = %v", o.Status)
	}
	if o.P50Ms <= 0 || o.P50Ms > 50 || o.P99Ms < o.P50Ms {
		t.Errorf("percentiles p50=%v p99=%v", o.P50Ms, o.P99Ms)
	}
	if len(o.Latency) != len(httpDurationBounds)+1 {
		t.Errorf("latency buckets = %d", len(o.Latency))
	}
	if o.UptimeSeconds < 59 {
		t.Errorf("uptime = %v", o.UptimeSeconds)
	}
}

func TestKickSessionRecordsEvent(t *testing.T) {
	s := New(DefaultConfig(), nil)
	s.sessions.Store("s1", &Session{ID: "s1", AccountID: "acct_a"})
	if s.KickSession("nope", "ops") {
		t.Error("unknown session reported as kicked")
	}
	if !s.KickSession("s1", "acct_ops") {
		t.Fatal("known session not kicked")
	}
	ev := s.Events(1, "")
	if len(ev) != 1 || ev[0].Kind != "admin" || ev[0].Account != "acct_a" {
		t.Errorf("event = %+v", ev)
	}
}

func TestDashboardRouteServedBeforeTunnels(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = "tunnel.test"
	s := New(cfg, nil)
	var seenRemote string
	s.SetDashboardRoute("Dashboard.tunnel.test.", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenRemote = r.RemoteAddr
		_, _ = w.Write([]byte("dash"))
	}))
	if !s.IsHostServed("dashboard.tunnel.test") || !s.IsHostServed("DASHBOARD.tunnel.test:443") {
		t.Error("dashboard host must count as served (so ACME may issue for it)")
	}
	if s.IsHostServed("other.tunnel.test") {
		t.Error("other host wrongly served")
	}

	// No TLS configured: served directly, with the visitor as RemoteAddr.
	req := httptest.NewRequest("GET", "http://dashboard.tunnel.test/api/x", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	rec := httptest.NewRecorder()
	s.handleHTTPRequest(rec, req)
	if rec.Code != 200 || rec.Body.String() != "dash" || seenRemote != "203.0.113.5:0" {
		t.Errorf("code=%d body=%q remote=%q", rec.Code, rec.Body.String(), seenRemote)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("dashboard responses must not be cached")
	}

	// TLS configured: plain HTTP is redirected, HTTPS is served with HSTS.
	s.config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "http://dashboard.tunnel.test/a?b=1", nil)
	s.handleHTTPRequest(rec, req)
	if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "https://dashboard.tunnel.test/a?b=1" {
		t.Errorf("redirect: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "https://dashboard.tunnel.test/", nil)
	s.handleHTTPRequest(rec, req)
	if rec.Code != 200 || rec.Header().Get("Strict-Transport-Security") == "" {
		t.Errorf("https: code=%d hsts=%q", rec.Code, rec.Header().Get("Strict-Transport-Security"))
	}

	// Unpublished again.
	s.SetDashboardRoute("", nil)
	if s.IsHostServed("dashboard.tunnel.test") {
		t.Error("still served after unpublishing")
	}
}

func TestDashboardRouteIsRateLimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = "tunnel.test"
	cfg.EdgeRatePerIP = 1
	cfg.EdgeRateBurst = 1
	s := New(cfg, nil)
	s.SetDashboardRoute("dashboard.tunnel.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	limited := 0
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "http://dashboard.tunnel.test/", nil)
		req.RemoteAddr = "203.0.113.9:1"
		rec := httptest.NewRecorder()
		s.handleHTTPRequest(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Error("a flood against the published dashboard was never rate limited")
	}
}
