package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

func TestByteBudget(t *testing.T) {
	var nilBudget *byteBudget
	if !nilBudget.take(1 << 40) {
		t.Error("a nil budget must be unlimited")
	}
	nilBudget.give(5) // must not panic

	b := newByteBudget(100)
	if !b.take(60) || b.take(41) || !b.take(40) {
		t.Error("take must admit up to the limit and refuse beyond it")
	}
	b.give(100)
	if b.used.Load() != 0 {
		t.Errorf("used = %d after giving everything back", b.used.Load())
	}
	if newByteBudget(0) != nil {
		t.Error("a zero budget means unlimited (nil)")
	}
}

// Uploads that would push buffered bodies past the budget get 503 instead of
// growing memory, bodies within the budget still go through intact, and the
// budget is fully returned afterwards.
func TestEdgeBodyBudgetRejectsExcessUploads(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBufferedBodyBytes = 1000
	s := New(cfg, nil)

	c1, c2 := net.Pipe()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()
	clientMux := mux.New(c2, mux.DefaultConfig())
	go clientMux.Run()

	tunnel := &Tunnel{ID: "tunnel-b", Type: proto.TunnelTypeHTTP, Subdomain: "budget", SessionID: "session-b"}
	s.tunnels.Store("budget", tunnel)
	s.sessions.Store("session-b", &Session{
		ID: "session-b", AccountID: "account-1", Mux: m,
		Tunnels: map[string]*Tunnel{"tunnel-b": tunnel}, CreatedAt: time.Now(), LastSeen: time.Now(),
		RemoteAddr: c1.RemoteAddr(),
	})

	go func() { // local app: report how many body bytes arrived
		for {
			stream, err := clientMux.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer stream.Close()
				req, err := http.ReadRequest(bufio.NewReader(stream))
				if err != nil {
					return
				}
				n, _ := io.Copy(io.Discard, req.Body)
				out := fmt.Sprintf("got %d", n)
				fmt.Fprintf(stream, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(out), out)
			}()
		}
	}()

	post := func(size int) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://budget.wirerift.com/up", bytes.NewReader(make([]byte, size)))
		req.Host = "budget.wirerift.com"
		rr := httptest.NewRecorder()
		s.handleHTTPRequest(rr, req)
		return rr
	}

	rr := post(5000)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("oversized upload: code = %d retry-after = %q, want 503 with Retry-After", rr.Code, rr.Header().Get("Retry-After"))
	}
	if got := s.bodyBudget.used.Load(); got != 0 {
		t.Fatalf("budget leaked %d bytes after a rejected upload", got)
	}

	rr = post(500)
	if rr.Code != http.StatusOK || rr.Body.String() != "got 500" {
		t.Fatalf("upload within budget: code = %d body = %q, want 200 \"got 500\"", rr.Code, rr.Body.String())
	}
	if got := s.bodyBudget.used.Load(); got != 0 {
		t.Fatalf("budget leaked %d bytes after a completed upload", got)
	}
}

// The inspector keeps a bounded amount of header data per message, still
// redacts credentials, and keeps small header sets whole.
func TestCaptureHeadersIsBounded(t *testing.T) {
	small := http.Header{"Accept": {"*/*"}, "Authorization": {"Bearer secret"}}
	got := captureHeaders(small)
	if got["Accept"] != "*/*" || got["Authorization"] != "[redacted]" || len(got) != 2 {
		t.Errorf("small header set altered: %v", got)
	}

	big := http.Header{}
	for i := 0; i < 200; i++ {
		big.Set(fmt.Sprintf("X-H-%03d", i), string(bytes.Repeat([]byte("v"), 4096)))
	}
	total := 0
	for k, v := range captureHeaders(big) {
		total += len(k) + len(v)
	}
	if limit := maxLoggedHeaderBytes + 2*len("…[truncated]"); total > limit {
		t.Errorf("captured %d header bytes, want <= %d", total, limit)
	}
}
