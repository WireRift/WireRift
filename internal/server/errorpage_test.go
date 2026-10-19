package server

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

func TestWriteEdgeErrorNegotiatesBrowsersAndClients(t *testing.T) {
	// API client / curl: identical to the plain http.Error body.
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, "Tunnel not found")
	if w.Code != 502 || w.Body.String() != "Tunnel not found\n" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("plain: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}

	// Browser: a self-contained HTML page with the message and a hint.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	w = httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, "Tunnel not found")
	body := w.Body.String()
	if w.Code != 502 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("html: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, want := range []string{"Tunnel not found", "No tunnel is registered", "502 Bad Gateway"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("error pages must not be cached")
	}

	// HEAD never gets a body page.
	r = httptest.NewRequest("HEAD", "/", nil)
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, "x")
	if strings.Contains(w.Header().Get("Content-Type"), "html") {
		t.Error("HEAD received an HTML page")
	}
}

func TestWriteEdgeErrorEscapesMessage(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	writeEdgeError(w, r, http.StatusBadGateway, `<script>alert(1)</script>`)
	if strings.Contains(w.Body.String(), "<script>") {
		t.Error("message was not HTML-escaped")
	}
}

func TestDefaultHintCoversCommonErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		msg    string
		want   string
	}{
		{502, "Session not found", "disconnected"},
		{502, "boom", "tunnel client did not answer"},
		{413, "x", "larger than"},
		{429, "x", "Wait a moment"},
		{403, "x", "not allowed"},
	} {
		if got := defaultHint(tc.status, tc.msg); !strings.Contains(got, tc.want) {
			t.Errorf("defaultHint(%d,%q) = %q, want %q", tc.status, tc.msg, got, tc.want)
		}
	}
	if defaultHint(418, "teapot") != "" {
		t.Error("unknown status should have no hint")
	}
}

// A visitor-controlled path such as /%zz must not crash the replay (the
// logged Path is decoded, so rebuilding the URL from it used to fail and the
// nil request was dereferenced), and encoded characters must survive.
func TestReplayRebuildsPoisonedPathsSafely(t *testing.T) {
	for _, path := range []string{"/%zz", "/a b", "/x?y", "/%00", "/ünï"} {
		u := (&url.URL{Path: path, RawQuery: "k=v"}).String()
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Errorf("path %q produced an unparsable replay URL %q: %v", path, u, err)
			continue
		}
		if req.URL.Path != path || req.URL.RawQuery != "k=v" {
			t.Errorf("path %q: round trip gave %q ? %q", path, req.URL.Path, req.URL.RawQuery)
		}
	}
}

// End to end: replaying a logged request whose (decoded) path is not a valid
// URL path must work, reach the local app escaped correctly, keep the query
// and the custom-domain Host, and carry both into the replay's own log.
func TestReplayRequestWithPoisonedPathHostAndQuery(t *testing.T) {
	s := New(DefaultConfig(), nil)
	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()
	clientMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()

	tunnel := &Tunnel{ID: "tun-p", Type: proto.TunnelTypeHTTP, SessionID: "sess-p", Subdomain: "p"}
	s.tunnels.Store("p", tunnel)
	s.sessions.Store("sess-p", &Session{ID: "sess-p", Mux: m, Tunnels: map[string]*Tunnel{"tun-p": tunnel}, CreatedAt: time.Now(), LastSeen: time.Now()})
	s.logMu.Lock()
	s.requestLogs = append(s.requestLogs, RequestLog{ID: "req_p", TunnelID: "tun-p", Method: "GET",
		Path: "/%zz", Query: "a=1&b=2", Host: "app.customer.org", ReqHeaders: map[string]string{}, ClientIP: "10.0.0.1"})
	s.logMu.Unlock()

	got := make(chan *http.Request, 1)
	go func() {
		stream, err := clientMux.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		req, err := http.ReadRequest(bufio.NewReader(stream))
		if err != nil {
			return
		}
		got <- req
		stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()

	replay, err := s.ReplayRequest("req_p") // used to panic: nil request
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Query != "a=1&b=2" || replay.Host != "app.customer.org" {
		t.Errorf("the replay's own log lost query/host: %+v", replay)
	}
	select {
	case req := <-got:
		if req.URL.Path != "/%zz" || req.URL.RawQuery != "a=1&b=2" || req.Host != "app.customer.org" {
			t.Errorf("local app received path %q query %q host %q", req.URL.Path, req.URL.RawQuery, req.Host)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the replay never reached the local app")
	}
}

// If the session is torn down between registering a tunnel and arming its
// expiry, the timer must not stay armed (it would pin the session for the TTL).
func TestArmExpiryDoesNotLeakAfterSessionRemoval(t *testing.T) {
	s := New(DefaultConfig(), nil)
	tunnel := &Tunnel{ID: "tun-x", Type: proto.TunnelTypeHTTP, ExpiresAt: time.Now().Add(time.Hour), closed: make(chan struct{})}
	gone := &Session{ID: "s", Tunnels: nil} // removeSession already ran: Tunnels == nil
	s.armExpiry(gone, tunnel)
	tunnel.mu.RLock()
	timer := tunnel.expiry
	tunnel.mu.RUnlock()
	if timer == nil {
		t.Fatal("no timer was created")
	}
	if timer.Stop() {
		t.Error("the expiry timer is still armed for a tunnel whose session is gone")
	}

	// A live registration keeps its timer.
	live := &Session{ID: "s2", Tunnels: map[string]*Tunnel{}}
	t2 := &Tunnel{ID: "tun-y", Type: proto.TunnelTypeHTTP, ExpiresAt: time.Now().Add(time.Hour), closed: make(chan struct{})}
	live.Tunnels[t2.ID] = t2
	s.armExpiry(live, t2)
	if !t2.expiry.Stop() {
		t.Error("a live tunnel lost its expiry timer")
	}
}
