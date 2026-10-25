package server

import (
	"net"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
)

// limitedServer returns a server whose token file defines one account.
func limitedServer(t *testing.T, acct auth.FileAccount) (*Server, string) {
	t.Helper()
	mgr := auth.NewManager()
	tf := &auth.TokenFile{}
	secret, _, err := tf.CreateToken(auth.CreateOptions{
		Account: acct.Name, Name: "t", MaxTunnels: acct.MaxTunnels, MaxSessions: acct.MaxSessions, RateLimit: acct.RateLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	mgr.ApplyTokenFile(tf)
	cfg := DefaultConfig()
	cfg.AuthManager = mgr
	return New(cfg, nil), secret
}

// login runs handleAuth over a pipe with the given token and returns the
// server-side result and the response the client saw.
func login(t *testing.T, s *Server, token string, remote net.Addr) (*Session, *proto.AuthResponse, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()

	resc := make(chan *proto.AuthResponse, 1)
	go func() {
		fw := proto.NewFrameWriter(c2)
		frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, &proto.AuthRequest{Token: token})
		_ = fw.Write(frame)
		f, err := proto.NewFrameReader(c2).Read()
		if err != nil {
			resc <- nil
			return
		}
		var r proto.AuthResponse
		_ = proto.DecodeJSONPayload(f, &r)
		resc <- &r
	}()
	sess, err := s.handleAuth(m, remote)
	return sess, <-resc, err
}

func TestAccountSessionLimit(t *testing.T) {
	s, secret := limitedServer(t, auth.FileAccount{Name: "acme", MaxSessions: 2})
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}

	var first *Session
	for i := 0; i < 2; i++ {
		sess, resp, err := login(t, s, secret, addr)
		if err != nil || !resp.OK {
			t.Fatalf("login %d: err=%v resp=%+v", i, err, resp)
		}
		if i == 0 {
			first = sess
		}
	}
	if _, resp, err := login(t, s, secret, addr); err == nil || resp.OK {
		t.Fatalf("third session was admitted (err=%v resp=%+v)", err, resp)
	}
	if s.accountSessionCount("acct_acme") != 2 {
		t.Errorf("session count = %d, want 2", s.accountSessionCount("acct_acme"))
	}

	// A freed slot is usable again, and the bootstrap account is not capped.
	s.removeSession(first.ID)
	if _, resp, err := login(t, s, secret, addr); err != nil || !resp.OK {
		t.Fatalf("login after a slot freed up: err=%v resp=%+v", err, resp)
	}
	for i := 0; i < 5; i++ {
		if _, resp, err := login(t, s, s.authManager.DevToken(), addr); err != nil || !resp.OK {
			t.Fatalf("bootstrap login %d: err=%v resp=%+v", i, err, resp)
		}
	}
}

func TestAccountTunnelLimitSpansSessions(t *testing.T) {
	s, secret := limitedServer(t, auth.FileAccount{Name: "acme", MaxTunnels: 2})
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1}

	sessions := make([]*Session, 0, 2)
	for i := 0; i < 2; i++ {
		sess, _, err := login(t, s, secret, addr)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, sess)
	}
	// One tunnel in each session already uses up the account's two.
	for i, sess := range sessions {
		sess.mu.Lock()
		sess.Tunnels["t"+string(rune('a'+i))] = &Tunnel{ID: "t" + string(rune('a'+i))}
		sess.mu.Unlock()
	}
	if n := s.accountTunnelCount("acct_acme"); n != 2 {
		t.Fatalf("account tunnel count = %d, want 2", n)
	}

	// A third tunnel request, on a session with room of its own, is refused.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	m := mux.New(c1, mux.DefaultConfig())
	go m.Run()
	errc := make(chan string, 1)
	go func() {
		f, err := proto.NewFrameReader(c2).Read()
		if err != nil {
			errc <- err.Error()
			return
		}
		var r proto.TunnelResponse
		_ = proto.DecodeJSONPayload(f, &r)
		errc <- r.Error
	}()
	req, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, &proto.TunnelRequest{Type: proto.TunnelTypeHTTP})
	s.handleTunnelRequest(m, sessions[0], req)
	if got := <-errc; got != "account tunnel limit reached" {
		t.Errorf("tunnel request error = %q, want the account limit", got)
	}
}

func TestAllowTunnelRequestIsPerAccount(t *testing.T) {
	s := New(DefaultConfig(), nil)
	acct := &auth.Account{ID: "acct_x", RateLimit: 2}
	first := &Session{ID: "s1", Account: acct}
	second := &Session{ID: "s2", Account: acct}

	if !s.allowTunnelRequest(first) || !s.allowTunnelRequest(second) {
		t.Fatal("the first two requests are within the burst")
	}
	// A new session of the same account shares the already spent allowance.
	if s.allowTunnelRequest(&Session{ID: "s3", Account: acct}) {
		t.Error("a fresh session must not reset the account's rate limit")
	}
	other := &Session{ID: "s4", Account: &auth.Account{ID: "acct_y", RateLimit: 2}}
	if !s.allowTunnelRequest(other) {
		t.Error("another account has its own allowance")
	}
	if !s.allowTunnelRequest(&Session{ID: "legacy"}) {
		t.Error("a session without an account falls back to the default limiter")
	}
}

func TestFailedLoginsThrottlePerIP(t *testing.T) {
	s, secret := limitedServer(t, auth.FileAccount{Name: "acme"})
	bad := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1}

	for i := 0; i < authFailBurst; i++ {
		if _, _, err := login(t, s, "wr_wrong", bad); err == nil {
			t.Fatal("wrong token accepted")
		}
	}
	// The bucket is empty: even the right token is refused from this IP...
	_, resp, err := login(t, s, secret, bad)
	if err == nil || resp.OK {
		t.Fatalf("throttled IP was admitted (err=%v resp=%+v)", err, resp)
	}
	// ...but another IP is unaffected, and the throttle is not sticky.
	good := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 4), Port: 1}
	if _, resp, err := login(t, s, secret, good); err != nil || !resp.OK {
		t.Fatalf("unrelated IP was refused: err=%v resp=%+v", err, resp)
	}
	s.authFails.Get("10.0.0.3").SetRate(1000)
	time.Sleep(20 * time.Millisecond)
	if _, resp, err := login(t, s, secret, bad); err != nil || !resp.OK {
		t.Fatalf("IP still blocked after the bucket refilled: err=%v resp=%+v", err, resp)
	}
}
