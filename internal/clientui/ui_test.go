package clientui

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

// env is a real server, a manager and the interface's handler on top of it.
type env struct {
	srv    *server.Server
	mgr    *Manager
	h      http.Handler
	key    string
	token  string
	domain string
	dir    string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	am := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", am
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	dir := t.TempDir()
	mgr := NewManager(client.DefaultConfig(), NewSettings(filepath.Join(dir, "cfg", "ui.json")), nil)
	t.Cleanup(mgr.Disconnect)
	key, _ := NewKey()
	return &env{srv: srv, mgr: mgr, h: NewHandler(mgr, key, "test"), key: key, token: am.DevToken(), domain: cfg.Domain, dir: dir}
}

// call is a request the page itself would make.
func (e *env) call(method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = "127.0.0.1:4041"
	req.AddCookie(&http.Cookie{Name: cookieName, Value: e.key})
	if method != http.MethodGet {
		req.Header.Set("X-WireRift-UI", "1")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *env) ok(t *testing.T, method, path string, body, out any) {
	t.Helper()
	code, b := e.call(method, path, body)
	if code/100 != 2 {
		t.Fatalf("%s %s: %d %s", method, path, code, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *env) connect(t *testing.T) {
	t.Helper()
	e.ok(t, "POST", "/api/connect", map[string]any{"server": e.srv.ControlAddr(), "token": e.token}, nil)
}

func (e *env) waitRows(t *testing.T, n int) []Row {
	t.Helper()
	for i := 0; i < 200; i++ {
		rows, _ := e.mgr.Traffic(0)
		if len(rows) >= n {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d rows", n)
	return nil
}

func (e *env) visit(t *testing.T, sub, method, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://"+e.srv.HTTPAddr()+path, strings.NewReader(body))
	req.Host = sub + "." + e.domain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestFullFlowThroughTheInterface(t *testing.T) {
	e := newEnv(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"method":%q,"path":%q,"body":%q}`, r.Method, r.URL.RequestURI(), b)
	}))
	defer local.Close()
	localPort := strings.TrimPrefix(local.URL, "http://127.0.0.1:")

	var st State
	e.ok(t, "GET", "/api/state", nil, &st)
	if st.State != StateDisconnected || len(st.Tunnels) != 0 {
		t.Fatalf("start state: %+v", st)
	}
	if code, _ := e.call("POST", "/api/tunnels", TunnelSpec{Type: "http", Local: localPort}); code != http.StatusBadRequest {
		t.Errorf("a tunnel before connecting: %d", code)
	}

	// A wrong token is refused with the server's own message and leaves us disconnected.
	code, b := e.call("POST", "/api/connect", map[string]any{"server": e.srv.ControlAddr(), "token": "wrong"})
	if code != http.StatusBadGateway || !strings.Contains(string(b), "authentication failed") {
		t.Errorf("wrong token: %d %s", code, b)
	}
	e.ok(t, "GET", "/api/state", nil, &st)
	if st.State != StateDisconnected || !strings.Contains(st.Error, "authentication failed") {
		t.Errorf("state after a refused login: %+v", st)
	}

	e.connect(t)
	if code, _ := e.call("POST", "/api/connect", map[string]any{"server": e.srv.ControlAddr(), "token": e.token}); code != http.StatusConflict {
		t.Errorf("second connect: %d", code)
	}
	e.ok(t, "GET", "/api/state", nil, &st)
	if st.State != StateConnected || !st.TokenSaved || st.ConnectedAt == nil {
		t.Fatalf("connected state: %+v", st)
	}
	if strings.Contains(fmt.Sprint(st), e.token) {
		t.Error("the state must never contain the token")
	}

	var tv TunnelView
	e.ok(t, "POST", "/api/tunnels", TunnelSpec{Type: "http", Local: localPort, Subdomain: "UiTest", TTL: "1h"}, &tv)
	if !strings.Contains(tv.URL, "uitest.") || tv.ExpiresAt == nil || tv.Local != "localhost:"+localPort {
		t.Fatalf("tunnel: %+v", tv)
	}

	status, body := e.visit(t, "uitest", "POST", "/orders?id=7", "payload")
	if status != 200 || !strings.Contains(body, `"payload"`) {
		t.Fatalf("visitor: %d %s", status, body)
	}
	rows := e.waitRows(t, 1)
	if rows[0].Method != "POST" || rows[0].Path != "/orders?id=7" || rows[0].Status != 200 || rows[0].BytesIn != 7 {
		t.Errorf("row: %+v", rows[0])
	}
	var d Detail
	e.ok(t, "GET", fmt.Sprintf("/api/traffic/%d", rows[0].ID), nil, &d)
	if d.Request.Body != "payload" || !strings.Contains(d.Response.Body, `"path":"/orders?id=7"`) || d.Response.Headers["Content-Type"][0] != "application/json" {
		t.Errorf("detail: %+v", d)
	}

	// Replay goes straight to the local service and shows its answer.
	var rr ReplayResult
	e.ok(t, "POST", fmt.Sprintf("/api/traffic/%d/replay", rows[0].ID), nil, &rr)
	if rr.Status != 200 || !strings.Contains(rr.Response.Body, `"body":"payload"`) {
		t.Errorf("replay: %+v", rr)
	}
	if again, _ := e.mgr.Traffic(0); len(again) != 1 {
		t.Error("a replay must not go through the tunnel, so it is not new traffic")
	}

	e.ok(t, "GET", "/api/state", nil, &st)
	if st.Stats.Requests != 1 || st.Stats.BytesIn != 7 || len(st.Tunnels) != 1 {
		t.Errorf("stats: %+v", st)
	}

	e.closeAndDisconnect(t, tv)
}

// closeAndDisconnect ends a flow: close the tunnel, clear the log, disconnect.
func (e *env) closeAndDisconnect(t *testing.T, tv TunnelView) {
	t.Helper()
	var st State
	// Closing the tunnel takes it away.
	e.ok(t, "DELETE", "/api/tunnels/"+tv.ID, nil, nil)
	e.ok(t, "GET", "/api/state", nil, &st)
	if len(st.Tunnels) != 0 {
		t.Errorf("tunnel still listed: %+v", st.Tunnels)
	}
	e.ok(t, "DELETE", "/api/traffic", nil, nil)
	if rows, last := e.mgr.Traffic(0); len(rows) != 0 || last != 0 {
		t.Error("clear left traffic behind")
	}

	e.ok(t, "POST", "/api/disconnect", nil, &st)
	if st.State != StateDisconnected {
		t.Errorf("after disconnect: %+v", st)
	}
	if code, _ := e.call("DELETE", "/api/tunnels/"+tv.ID, nil); code != http.StatusBadRequest {
		t.Errorf("closing while disconnected: %d", code)
	}
}

func TestTCPTunnelAndUnreachableLocalService(t *testing.T) {
	e := newEnv(t)
	e.connect(t)
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		if c, err := echo.Accept(); err == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	var tv TunnelView
	e.ok(t, "POST", "/api/tunnels", TunnelSpec{Type: "tcp", Local: echo.Addr().String()}, &tv)
	if tv.Port == 0 || tv.Type != "tcp" {
		t.Fatalf("tcp tunnel: %+v", tv)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tv.Port))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "abc")
	io.ReadFull(c, make([]byte, 3))
	c.Close()
	rows := e.waitRows(t, 1)
	if rows[0].Kind != "tcp" || rows[0].BytesIn != 3 || rows[0].BytesOut != 3 {
		t.Errorf("tcp row: %+v", rows[0])
	}
	var d Detail
	e.ok(t, "GET", fmt.Sprintf("/api/traffic/%d", rows[0].ID), nil, &d)
	if code, _ := e.call("POST", fmt.Sprintf("/api/traffic/%d/replay", rows[0].ID), nil); code != http.StatusBadRequest {
		t.Errorf("replaying a tcp connection: %d", code)
	}

	// Nothing listens on the forwarded port: the visitor gets a 502, and we see why.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	e.ok(t, "POST", "/api/tunnels", TunnelSpec{Type: "http", Local: dead, Subdomain: "dead"}, nil)
	if status, _ := e.visit(t, "dead", "GET", "/x", ""); status != 502 {
		t.Fatalf("visitor status %d", status)
	}
	var found Row
	for _, r := range e.waitRows(t, 2) {
		if r.Kind == "http" {
			found = r
		}
	}
	if found.Error == "" || found.Status != 502 {
		t.Errorf("unreachable row: %+v", found)
	}
	e.mgr.record(client.Exchange{}) // a stray empty exchange must not break the log
	if _, err := e.mgr.Replay(found.ID); err != nil {
		t.Errorf("replay of a request whose local service is down should report it in the result, not fail: %v", err)
	}
	res, _ := e.mgr.Replay(found.ID)
	if res.Error == "" {
		t.Error("the replay result should carry the connection error")
	}
}

func TestTunnelValidation(t *testing.T) {
	e := newEnv(t)
	e.connect(t)
	for name, spec := range map[string]TunnelSpec{
		"no port":       {Type: "http"},
		"bad port":      {Type: "http", Local: "99999"},
		"bad host":      {Type: "http", Local: "bad host!:80"},
		"bad type":      {Type: "udp", Local: "80"},
		"bad ttl":       {Type: "http", Local: "80", TTL: "soon"},
		"zero ttl":      {Type: "http", Local: "80", TTL: "0s"},
		"bad auth":      {Type: "http", Local: "80", Auth: "nocolon"},
		"empty user":    {Type: "http", Local: "80", Auth: ":pw"},
		"bad subdomain": {Type: "http", Local: "80", Subdomain: "-bad-"},
	} {
		if code, b := e.call("POST", "/api/tunnels", spec); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	// Options the server accepts all go through.
	var tv TunnelView
	e.ok(t, "POST", "/api/tunnels", TunnelSpec{Type: "http", Local: "127.0.0.1:80", Subdomain: "opts", Auth: "u:p", PIN: "1234", Allow: "10.0.0.0/8, 192.168.1.1", Inspect: true}, &tv)
	if tv.Local != "127.0.0.1:80" {
		t.Errorf("local: %q", tv.Local)
	}
	if code, _ := e.call("POST", "/api/connect", map[string]any{"server": ""}); code != http.StatusConflict && code != http.StatusBadGateway {
		t.Errorf("empty server: %d", code)
	}
}

func TestConnectValidationAndSavedLogin(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.call("POST", "/api/connect", map[string]any{"server": "", "token": "x"}); code != http.StatusBadGateway {
		t.Errorf("empty server: %d", code)
	}
	if code, b := e.call("POST", "/api/connect", map[string]any{"server": e.srv.ControlAddr()}); code != http.StatusBadGateway || !strings.Contains(string(b), "token is required") {
		t.Errorf("no token: %d %s", code, b)
	}
	// Remembering writes the token with owner-only permissions; a new manager reads it.
	e.ok(t, "POST", "/api/connect", map[string]any{"server": e.srv.ControlAddr(), "token": e.token, "remember": true}, nil)
	path := filepath.Join(e.dir, "cfg", "ui.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("saved login is %v, want 0600", fi.Mode().Perm())
	}
	var st State
	e.ok(t, "GET", "/api/state", nil, &st)
	if !st.Remembered {
		t.Error("remembered flag missing")
	}
	e.mgr.Disconnect()
	again := NewManager(client.DefaultConfig(), NewSettings(path), nil)
	ast := again.State()
	if ast.Server != e.srv.ControlAddr() || !ast.TokenSaved || !ast.Remembered {
		t.Errorf("restart did not restore the login: %+v", ast)
	}
	if err := again.Connect("", "", false); err == nil {
		t.Error("an empty server must be refused")
	}
	if err := again.Connect(e.srv.ControlAddr(), "", false); err != nil {
		t.Fatalf("an empty token should reuse the saved one: %v", err)
	}
	again.Disconnect()

	// Without "remember" only the server is kept.
	e.ok(t, "POST", "/api/connect", map[string]any{"server": e.srv.ControlAddr(), "token": e.token}, nil)
	if got := NewSettings(path).Load(); got.Token != "" || got.Server == "" {
		t.Errorf("saved without remember: %+v", got)
	}
	e.ok(t, "POST", "/api/forget", nil, &st)
	if st.TokenSaved || st.Remembered {
		t.Errorf("forget: %+v", st)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("forget left the file behind")
	}
}

func TestSettingsEdgeCases(t *testing.T) {
	var none *Settings
	if got := none.Load(); got.Server != "" || got.Token != "" || got.Presets != nil {
		t.Error("nil settings must be empty")
	}
	if err := none.Save(Saved{Server: "x"}); err != nil {
		t.Error(err)
	}
	if err := NewSettings("").Save(Saved{Server: "x"}); err != nil {
		t.Error(err)
	}
	s := NewSettings(filepath.Join(t.TempDir(), "ui.json"))
	if got := s.Load(); got.Server != "" || got.Token != "" {
		t.Errorf("missing file: %+v", got)
	}
	if err := s.Save(Saved{}); err != nil {
		t.Errorf("clearing a missing file: %v", err)
	}
	os.WriteFile(s.path, []byte("{not json"), 0o600)
	if got := s.Load(); got.Server != "" || got.Token != "" {
		t.Errorf("garbage file: %+v", got)
	}
	// A directory where the file should be makes saving fail with an error.
	bad := NewSettings(filepath.Join(t.TempDir(), "d"))
	os.MkdirAll(filepath.Join(bad.path, "x"), 0o700)
	if err := bad.Save(Saved{Server: "x"}); err == nil {
		t.Error("saving over a directory should fail")
	}
	if err := bad.Save(Saved{}); err == nil {
		t.Error("removing a non-empty directory should fail")
	}
	if p, err := DefaultSettingsPath(); err == nil && !strings.HasSuffix(p, filepath.Join("wirerift", "ui.json")) {
		t.Errorf("default path: %s", p)
	}
}

func TestInterfaceRefusesStrangers(t *testing.T) {
	e := newEnv(t)
	do := func(method, path, host string, cookie bool, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Host = host
		if cookie {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: e.key})
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	// DNS rebinding: a page on another name that resolves to 127.0.0.1.
	for _, host := range []string{"evil.example:4041", "127.0.0.1.evil.example", "10.0.0.5:4041"} {
		if rec := do("GET", "/", host, true, nil); rec.Code != http.StatusForbidden {
			t.Errorf("host %q: %d", host, rec.Code)
		}
	}
	for _, host := range []string{"127.0.0.1:4041", "localhost:4041", "[::1]:4041", "LOCALHOST"} {
		if rec := do("GET", "/", host, true, nil); rec.Code != http.StatusOK {
			t.Errorf("host %q should be allowed: %d", host, rec.Code)
		}
	}
	// No key, wrong key.
	if rec := do("GET", "/", "127.0.0.1:1", false, nil); rec.Code != http.StatusForbidden {
		t.Errorf("no key: %d", rec.Code)
	}
	if rec := do("GET", "/?k=wrong", "127.0.0.1:1", false, nil); rec.Code != http.StatusForbidden {
		t.Errorf("wrong key: %d", rec.Code)
	}
	if rec := do("GET", "/api/state", "127.0.0.1:1", false, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("api without cookie: %d", rec.Code)
	}
	// The right key sets an HttpOnly, same-site cookie and moves on.
	rec := do("GET", "/?k="+e.key, "127.0.0.1:1", false, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("key: %d", rec.Code)
	}
	ck := rec.Result().Cookies()
	if len(ck) != 1 || !ck[0].HttpOnly || ck[0].SameSite != http.SameSiteStrictMode || ck[0].Value != e.key {
		t.Errorf("cookie: %+v", ck)
	}
	// Changes must come from the page: header and same origin.
	if rec := do("POST", "/api/disconnect", "127.0.0.1:1", true, nil); rec.Code != http.StatusForbidden {
		t.Errorf("post without the page header: %d", rec.Code)
	}
	if rec := do("POST", "/api/disconnect", "127.0.0.1:1", true, map[string]string{"X-WireRift-UI": "1", "Origin": "http://evil.example"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin post: %d", rec.Code)
	}
	if rec := do("POST", "/api/disconnect", "127.0.0.1:1", true, map[string]string{"X-WireRift-UI": "1", "Origin": "http://127.0.0.1:1"}); rec.Code != http.StatusOK {
		t.Errorf("same-origin post: %d", rec.Code)
	}
	// The page carries a nonce policy and no sniffing or framing.
	page := do("GET", "/", "127.0.0.1:1", true, nil)
	csp := page.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "nonce-") || page.Header().Get("X-Frame-Options") != "DENY" || page.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers: csp=%q", csp)
	}
	if strings.Contains(page.Body.String(), "{{") {
		t.Error("an unreplaced placeholder is left in the page")
	}
	nonce := strings.TrimSuffix(strings.SplitN(csp, "script-src 'nonce-", 2)[1][:strings.Index(strings.SplitN(csp, "script-src 'nonce-", 2)[1], "'")], "")
	if !strings.Contains(page.Body.String(), `<script nonce="`+nonce+`">`) {
		t.Error("the script does not carry the policy's nonce")
	}
	if rec := do("GET", "/nope", "127.0.0.1:1", true, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", rec.Code)
	}
}

func TestAPIMethodsAndPaths(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"POST", "/api/state", http.StatusMethodNotAllowed},
		{"GET", "/api/connect", http.StatusMethodNotAllowed},
		{"GET", "/api/disconnect", http.StatusMethodNotAllowed},
		{"GET", "/api/forget", http.StatusMethodNotAllowed},
		{"GET", "/api/tunnels", http.StatusMethodNotAllowed},
		{"GET", "/api/tunnels/x", http.StatusMethodNotAllowed},
		{"DELETE", "/api/tunnels/", http.StatusNotFound},
		{"PUT", "/api/traffic", http.StatusMethodNotAllowed},
		{"GET", "/api/traffic/abc", http.StatusNotFound},
		{"GET", "/api/traffic/999", http.StatusNotFound},
		{"POST", "/api/traffic/999", http.StatusMethodNotAllowed},
		{"GET", "/api/traffic/999/replay", http.StatusMethodNotAllowed},
		{"POST", "/api/traffic/999/replay", http.StatusBadRequest},
		{"GET", "/api/traffic/999/other", http.StatusNotFound},
	} {
		if code, b := e.call(c.method, c.path, nil); code != c.want {
			t.Errorf("%s %s: %d (want %d) %s", c.method, c.path, code, c.want, b)
		}
	}
	for _, p := range []string{"/api/connect", "/api/tunnels"} {
		req := httptest.NewRequest("POST", p, strings.NewReader("{broken"))
		req.Host = "127.0.0.1:1"
		req.AddCookie(&http.Cookie{Name: cookieName, Value: e.key})
		req.Header.Set("X-WireRift-UI", "1")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s with a broken body: %d", p, rec.Code)
		}
	}
}

func TestLocalAddress(t *testing.T) {
	for in, want := range map[string]string{
		"3000": "localhost:3000", " 8080 ": "localhost:8080", "host:80": "host:80", "127.0.0.1:9": "127.0.0.1:9",
		"my-host.local:1": "my-host.local:1", "[::1]:80": "[::1]:80",
	} {
		if got, err := LocalAddress(in); err != nil || got != want {
			t.Errorf("LocalAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "70000", "x", "host:", ":80", "a b:80", "host:port", "http://x:80"} {
		if got, err := LocalAddress(bad); err == nil {
			t.Errorf("LocalAddress(%q) accepted as %q", bad, got)
		}
	}
}

func TestTrafficLogIsBoundedAndCounts(t *testing.T) {
	m := NewManager(client.DefaultConfig(), nil, nil)
	for i := 1; i <= trafficKeep+50; i++ {
		x := client.Exchange{ID: uint64(i), Status: 200, BytesIn: 1, BytesOut: 2}
		if i%100 == 0 {
			x.Status = 500
		}
		m.record(x)
	}
	rows, last := m.Traffic(0)
	if len(rows) != trafficKeep || last != uint64(trafficKeep+50) || rows[0].ID != 51 {
		t.Errorf("kept %d rows, last %d, first %d", len(rows), last, rows[0].ID)
	}
	if newer, _ := m.Traffic(last - 2); len(newer) != 2 {
		t.Errorf("since: %d rows", len(newer))
	}
	st := m.State()
	if st.Stats.Requests != trafficKeep+50 || st.Stats.Errors != 10 || st.Stats.BytesIn != trafficKeep+50 {
		t.Errorf("stats: %+v", st.Stats)
	}
	if _, ok := m.Detail(1); ok {
		t.Error("a dropped exchange should be gone")
	}
	m.Prefill("srv:1", "tok")
	m.Prefill("other:2", "other")
	if s := m.State(); s.Server != "srv:1" || !s.TokenSaved {
		t.Errorf("prefill should only fill what is empty: %+v", s)
	}
}

func TestMessageHandlesTextBinaryAndGzip(t *testing.T) {
	if m := message(nil, []byte("héllo\n"), false); m.Body != "héllo\n" || m.Binary || m.Headers == nil {
		t.Errorf("text: %+v", m)
	}
	if m := message(http.Header{}, []byte{0x00, 0x01, 0xff}, true); !m.Binary || m.Body != "" || !m.Truncated {
		t.Errorf("binary: %+v", m)
	}
	if m := message(http.Header{}, nil, false); m.Binary || m.Body != "" {
		t.Errorf("empty: %+v", m)
	}
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write([]byte(strings.Repeat("compressed text ", 50)))
	zw.Close()
	h := http.Header{"Content-Encoding": {"gzip"}}
	if m := message(h, zb.Bytes(), false); !strings.HasPrefix(m.Body, "compressed text") {
		t.Errorf("gzip should be decoded: %+v", m)
	}
	if m := message(h, zb.Bytes()[:zb.Len()/2], true); !strings.HasPrefix(m.Body, "compressed") {
		t.Errorf("a cut-off gzip body should still show what it can: %.40q", m.Body)
	}
	if m := message(h, []byte("not gzip"), false); m.Body != "not gzip" {
		t.Errorf("a body labelled gzip that is not: %+v", m)
	}
}

func TestReplayRefusesWhatItCannotDoFaithfully(t *testing.T) {
	m := NewManager(client.DefaultConfig(), nil, nil)
	if _, err := m.Replay(1); err == nil {
		t.Error("unknown exchange")
	}
	m.record(client.Exchange{ID: 1, Kind: "http", Method: "POST", Path: "/", LocalAddr: "localhost:1", ReqTruncated: true})
	if _, err := m.Replay(1); err == nil || !strings.Contains(err.Error(), "longer") {
		t.Errorf("truncated body: %v", err)
	}
	m.record(client.Exchange{ID: 2, Kind: "http", Method: "BAD METHOD", Path: "/", LocalAddr: "localhost:1"})
	if _, err := m.Replay(2); err == nil {
		t.Error("an unusable method should fail to rebuild")
	}
	m.record(client.Exchange{ID: 3, Kind: "websocket", LocalAddr: "localhost:1"})
	if _, err := m.Replay(3); err == nil {
		t.Error("websocket")
	}
}

func TestReplayKeepsHeadersAndLimitsTheBody(t *testing.T) {
	got := make(chan http.Header, 1)
	big := strings.Repeat("x", replayLimit+10)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
		_, _ = io.WriteString(w, big)
	}))
	defer local.Close()
	m := NewManager(client.DefaultConfig(), nil, nil)
	m.record(client.Exchange{ID: 1, Kind: "http", Method: "GET", Path: "/a?b=1", Host: "pub.example", LocalAddr: strings.TrimPrefix(local.URL, "http://"),
		ReqHeader: http.Header{"X-Keep": {"1"}, "Connection": {"close"}, "Content-Length": {"99"}}})
	res, err := m.Replay(1)
	if err != nil {
		t.Fatal(err)
	}
	h := <-got
	if h.Get("X-Keep") != "1" || h.Get("Content-Length") == "99" {
		t.Errorf("headers: %v", h)
	}
	if res.Status != 302 || !res.Response.Truncated || res.Response.BodyBytes != replayLimit {
		t.Errorf("a redirect is shown, not followed, and a big body is cut: %+v", res.Response)
	}
	time.Sleep(10 * time.Millisecond)
}

func TestPresets(t *testing.T) {
	e := newEnv(t)
	var list []Preset
	e.ok(t, "GET", "/api/presets", nil, &list)
	if len(list) != 0 {
		t.Fatalf("fresh install has presets: %v", list)
	}
	web := Preset{Name: "web", TunnelSpec: TunnelSpec{Type: "http", Local: "3000", Subdomain: "myapp", PIN: "1234"}}
	e.ok(t, "POST", "/api/presets", web, &list)
	e.ok(t, "POST", "/api/presets", Preset{Name: "db", TunnelSpec: TunnelSpec{Type: "tcp", Local: "db:5432"}}, &list)
	web.Local = "4000"
	web.Name = "WEB" // same name, other case: replaces
	e.ok(t, "POST", "/api/presets", web, &list)
	if len(list) != 2 || list[0].Local != "4000" || list[0].PIN != "1234" {
		t.Fatalf("presets: %+v", list)
	}

	// They survive connect, forget and a restart.
	e.connect(t)
	e.ok(t, "POST", "/api/forget", nil, nil)
	e.mgr.Disconnect()
	again := NewManager(client.DefaultConfig(), NewSettings(filepath.Join(e.dir, "cfg", "ui.json")), nil)
	if got := again.Presets(); len(got) != 2 {
		t.Fatalf("lost after forget/restart: %+v", got)
	}

	for _, bad := range []Preset{
		{Name: "", TunnelSpec: TunnelSpec{Type: "http", Local: "80"}},
		{Name: strings.Repeat("x", 41), TunnelSpec: TunnelSpec{Type: "http", Local: "80"}},
		{Name: "a", TunnelSpec: TunnelSpec{Type: "udp", Local: "80"}},
		{Name: "a", TunnelSpec: TunnelSpec{Type: "http", Local: "nope"}},
	} {
		if code, _ := e.call("POST", "/api/presets", bad); code != http.StatusBadRequest {
			t.Errorf("%+v accepted: %d", bad, code)
		}
	}
	e.ok(t, "DELETE", "/api/presets?name=db", nil, &list)
	if len(list) != 1 || list[0].Name != "WEB" {
		t.Fatalf("after delete: %+v", list)
	}
	if code, _ := e.call("PUT", "/api/presets", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", code)
	}

	// Limits and no-save mode.
	for i := 0; i < maxPresets; i++ {
		_ = e.mgr.SavePreset(Preset{Name: fmt.Sprint("p", i), TunnelSpec: TunnelSpec{Type: "tcp", Local: "1"}})
	}
	if err := e.mgr.SavePreset(Preset{Name: "one-too-many", TunnelSpec: TunnelSpec{Type: "tcp", Local: "1"}}); err == nil {
		t.Error("preset limit not enforced")
	}
	off := NewManager(client.DefaultConfig(), nil, nil)
	if err := off.SavePreset(web); err == nil {
		t.Error("-no-save must refuse presets")
	}
	if err := off.DeletePreset("x"); err != nil || len(off.Presets()) != 0 {
		t.Error("nil settings must be harmless")
	}
}
