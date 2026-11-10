package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
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

func TestStartRecordsHistoryAndEvent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.HTTPSAddr = "127.0.0.1:0", "127.0.0.1:0", ""
	cfg.TCPAddrRange = "42200-42210"
	cfg.CertificateExpiry = func() time.Time { return time.Now().Add(48 * time.Hour) }
	cfg.PersistenceErrors = func() uint64 { return 3 }
	s := New(cfg, nil)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if len(s.History()) < 1 {
		t.Error("the sampler must take a first sample at start")
	}
	if ev := s.Events(0, ""); len(ev) == 0 || ev[len(ev)-1].Message != "server started" {
		t.Errorf("events = %+v", ev)
	}
	s.tunnels.Store("tcp:42200", &Tunnel{ID: "t", AccountID: "acct_a", Type: "tcp"})
	s.tcpPorts.Store(42200, true)
	o := s.AdminOverview()
	if o.CertExpiry == nil || o.PersistenceErrors != 3 || o.TCPTunnels != 1 || o.TCPPortsUse != 1 || o.TCPPortsMax != 11 {
		t.Errorf("overview = %+v", o)
	}
	if o.OpenFDs == 0 {
		t.Error("open fds should be counted or -1")
	}
}

func TestLatencySummaryEmptyAndOverflow(t *testing.T) {
	s := New(DefaultConfig(), nil)
	avg, p50, _, p99, b := s.latencySummary(0)
	if avg != 0 || p50 != 0 || p99 != 0 || len(b) != len(httpDurationBounds)+1 {
		t.Errorf("empty: %v %v %v %d", avg, p50, p99, len(b))
	}
	s.observeHTTPRequest(200, 30*time.Second) // beyond the last bound
	_, p50, _, _, b = s.latencySummary(1)
	if p50 != httpDurationBounds[len(httpDurationBounds)-1]*1000 || b[len(b)-1].Count != 1 {
		t.Errorf("overflow bucket: p50=%v last=%+v", p50, b[len(b)-1])
	}
}

func TestHeldTCPPortsAreSkippedPersistedAndExpire(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TCPAddrRange = "43000-43004"
	cfg.OfflineGrace = time.Minute
	cfg.HeldFile = t.TempDir() + "/held.json"
	s := New(cfg, nil)

	s.holdPort(43002, "acct_a")
	if owner, held := s.heldPortBy(43002); !held || owner != "acct_a" {
		t.Fatalf("heldPortBy = %q %v", owner, held)
	}
	seen := map[int]bool{}
	for i := 0; i < 4; i++ { // every free port of the range, never the reserved one
		p, err := s.allocatePort()
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		seen[p] = true
	}
	if seen[43002] || len(seen) != 4 {
		t.Errorf("allocated %v: the reserved port must be skipped", seen)
	}
	if _, err := s.allocatePort(); err == nil {
		t.Error("the range has only the reserved port left; allocation must fail")
	}

	s.holdSubdomain("shop", "acct_a")
	s.saveHeld()
	s2 := New(cfg, nil)
	s2.loadHeld()
	if owner, held := s2.heldPortBy(43002); !held || owner != "acct_a" {
		t.Errorf("port reservation lost over a restart: %q %v", owner, held)
	}
	if owner, held := s2.heldBy("shop"); !held || owner != "acct_a" {
		t.Errorf("subdomain reservation lost over a restart: %q %v", owner, held)
	}

	s.held.Store(tcpHoldKey(43003), heldName{accountID: "acct_a", until: time.Now().Add(-time.Second)})
	if _, held := s.heldPortBy(43003); held {
		t.Error("an expired reservation still counts")
	}
}

func TestListenTCPForRequestRules(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TCPAddrRange = "43100-43110"
	cfg.OfflineGrace = time.Minute
	cfg.TCPBindHost = "127.0.0.1"
	s := New(cfg, nil)
	alice := &Session{ID: "s1", AccountID: "acct_alice"}
	bob := &Session{ID: "s2", AccountID: "acct_bob"}

	if _, _, err := s.listenTCPForRequest(alice, &proto.TunnelRequest{RemotePort: 80}); err != errPortOutOfRange {
		t.Errorf("out of range: %v", err)
	}
	s.holdPort(43105, "acct_alice")
	if _, _, err := s.listenTCPForRequest(bob, &proto.TunnelRequest{RemotePort: 43105}); err != errPortTaken {
		t.Errorf("another account asking for a reserved port: %v", err)
	}
	l, port, err := s.listenTCPForRequest(alice, &proto.TunnelRequest{RemotePort: 43105})
	if err != nil || port != 43105 {
		t.Fatalf("the owner asking for its reserved port: %d %v", port, err)
	}
	l.Close()
	s.releasePort(43105)

	// A port held by a foreign program is reported as taken, not as an error.
	foreign, err := net.Listen("tcp", "127.0.0.1:43106")
	if err != nil {
		t.Skipf("cannot occupy a port: %v", err)
	}
	defer foreign.Close()
	if _, _, err := s.listenTCPForRequest(alice, &proto.TunnelRequest{RemotePort: 43106}); err != errPortTaken {
		t.Errorf("port in use by another program: %v", err)
	}
	if _, loaded := s.tcpPorts.Load(43106); loaded {
		t.Error("a failed bind must not leave the port marked as allocated")
	}
}

func TestConnectInfoDescribesTheServer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domain = "tunnel.example.com"
	cfg.Version = "9.9.9"
	cfg.ControlAddr = "127.0.0.1:4443"
	cfg.PublicScheme = "https"
	cfg.PublicPort = 443
	s := New(cfg, nil)
	info := s.ConnectInfo()
	if info.Domain != "tunnel.example.com" || info.Version != "9.9.9" || info.ControlPort != 4443 {
		t.Errorf("basics: %+v", info)
	}
	if info.ServerArg != "tunnel.example.com:4443" || info.ControlTLS {
		t.Errorf("plain control plane: %q tls=%v", info.ServerArg, info.ControlTLS)
	}
	if info.PublicScheme != "https" || info.TCPPortEnd < info.TCPPortStart {
		t.Errorf("public side: %+v", info)
	}

	cfg.ControlTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	cfg.PublicScheme = ""
	info = New(cfg, nil).ConnectInfo()
	if info.ServerArg != "tls://tunnel.example.com:4443" || !info.ControlTLS {
		t.Errorf("TLS control plane: %q tls=%v", info.ServerArg, info.ControlTLS)
	}
	if info.PublicScheme != "http" {
		t.Errorf("default scheme: %q", info.PublicScheme)
	}
}

func TestAccountTrafficCountersAppearInOverview(t *testing.T) {
	s := New(DefaultConfig(), nil)
	c := s.accountCounters("acct_x")
	if s.accountCounters("acct_x") != c {
		t.Fatal("counters must be shared per account")
	}
	c.requests.Add(3)
	c.bytesIn.Add(100)
	c.bytesOut.Add(2000)
	var got *AccountUsage
	for _, u := range s.AdminOverview().Accounts {
		if u.Account == "acct_x" {
			u := u
			got = &u
		}
	}
	if got == nil || got.Requests != 3 || got.BytesIn != 100 || got.BytesOut != 2000 {
		t.Fatalf("usage = %+v", got)
	}
}
