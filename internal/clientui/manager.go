// Package clientui is the client's local web interface: connect to a server,
// open and close tunnels, and watch the traffic that passes through them.
package clientui

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wirerift/wirerift/internal/client"
)

const (
	trafficKeep = 1000     // exchanges kept in memory
	captureBody = 64 << 10 // body bytes kept per direction and exchange
	replayLimit = 256 << 10
)

// Connection states shown by the UI.
const (
	StateDisconnected = "disconnected"
	StateConnected    = "connected"
	StateReconnecting = "reconnecting"
	StateFailed       = "failed"
)

// Manager owns the client connection, the tunnels and the captured traffic.
type Manager struct {
	base     client.Config
	logger   *slog.Logger
	settings *Settings

	mu          sync.Mutex
	cl          *client.Client
	server      string
	token       string // never sent to the page
	connectedAt time.Time
	lastErr     string
	remembered  bool // the token is stored on disk

	tmu     sync.Mutex
	traffic []client.Exchange
	stats   Stats
}

// Stats are totals since the UI started or the traffic was cleared.
type Stats struct {
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"` // 5xx or unreachable
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// NewManager returns a manager that builds clients from base (version, TLS
// settings) and remembers the server and, on request, the token in settings
// (nil: nothing is stored).
func NewManager(base client.Config, settings *Settings, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m := &Manager{base: base, settings: settings, logger: logger}
	if saved := settings.Load(); saved.Server != "" {
		m.server, m.token, m.remembered = saved.Server, saved.Token, saved.Token != ""
	}
	return m
}

// Prefill sets the server and token the form starts with when nothing was saved.
func (m *Manager) Prefill(server, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server == "" {
		m.server = server
	}
	if m.token == "" {
		m.token = token
	}
}

// TunnelView is a tunnel as the page shows it.
type TunnelView struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	URL       string     `json:"url,omitempty"`
	Port      int        `json:"port,omitempty"`
	Local     string     `json:"local"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// State is what GET /api/state returns.
type State struct {
	State       string       `json:"state"`
	Error       string       `json:"error,omitempty"`
	Server      string       `json:"server"`
	TokenSaved  bool         `json:"token_saved"` // a token is held (never shown)
	Remembered  bool         `json:"remembered"`  // and it is stored on disk
	ConnectedAt *time.Time   `json:"connected_at,omitempty"`
	Tunnels     []TunnelView `json:"tunnels"`
	Stats       Stats        `json:"stats"`
}

// State reports the connection, the open tunnels and the totals.
func (m *Manager) State() State {
	m.mu.Lock()
	cl, srv, tok, at, lastErr, rem := m.cl, m.server, m.token, m.connectedAt, m.lastErr, m.remembered
	m.mu.Unlock()

	st := State{State: StateDisconnected, Server: srv, TokenSaved: tok != "", Error: lastErr, Tunnels: []TunnelView{}}
	st.Remembered = rem
	if cl != nil {
		select {
		case <-cl.Failed():
			st.State = StateFailed
			if err := cl.Err(); err != nil {
				st.Error = err.Error()
			}
		default:
			st.State = StateReconnecting
			if cl.IsConnected() {
				st.State = StateConnected
				st.Error = ""
			}
		}
		st.ConnectedAt = &at
		for _, t := range cl.Tunnels() {
			v := TunnelView{ID: t.ID, Type: t.Type, URL: t.PublicURL, Port: t.Port, Local: t.LocalAddr}
			if !t.ExpiresAt.IsZero() {
				exp := t.ExpiresAt
				v.ExpiresAt = &exp
			}
			st.Tunnels = append(st.Tunnels, v)
		}
	}
	m.tmu.Lock()
	st.Stats = m.stats
	m.tmu.Unlock()
	return st
}

// ErrBusy is returned when a connection already exists.
var ErrBusy = errors.New("already connected: disconnect first")

// Connect logs in to server. An empty token reuses the held one. remember
// stores the server and token on this computer; otherwise only the server.
func (m *Manager) Connect(server, token string, remember bool) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return errors.New("server address is required")
	}
	m.mu.Lock()
	if m.cl != nil {
		m.mu.Unlock()
		return ErrBusy
	}
	if token == "" {
		token = m.token
	}
	m.mu.Unlock()
	if token == "" {
		return errors.New("token is required")
	}

	cfg := m.base
	cfg.ServerAddr, cfg.Token, cfg.Reconnect = server, token, true
	cfg.OnExchange, cfg.CaptureBody = m.record, captureBody
	c := client.New(cfg, m.logger)
	if err := c.Connect(); err != nil {
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	m.cl, m.server, m.token, m.connectedAt, m.lastErr, m.remembered = c, server, token, time.Now(), "", remember
	m.mu.Unlock()
	saved := m.settings.Load()
	saved.Server, saved.Token = server, ""
	if remember {
		saved.Token = token
	}
	_ = m.settings.Save(saved)
	return nil
}

// Disconnect closes the connection and every tunnel on it. The captured
// traffic stays for inspection.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	c := m.cl
	m.cl, m.lastErr = nil, ""
	m.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// Forget deletes the stored token and server and drops the held token.
func (m *Manager) Forget() error {
	m.mu.Lock()
	m.token, m.remembered = "", false
	m.mu.Unlock()
	saved := m.settings.Load()
	saved.Server, saved.Token = "", ""
	return m.settings.Save(saved)
}

// TunnelSpec is a tunnel to open.
type TunnelSpec struct {
	Type      string `json:"type"`  // http or tcp
	Local     string `json:"local"` // port or host:port
	Subdomain string `json:"subdomain"`
	Domain    string `json:"domain"`
	Auth      string `json:"auth"` // user:password
	PIN       string `json:"pin"`
	Allow     string `json:"allow"` // comma-separated IPs or CIDRs
	TTL       string `json:"ttl"`   // 30m, 2h
	Inspect   bool   `json:"inspect"`
}

// LocalAddress normalizes "3000" or "host:3000" to host:port (host defaults to
// localhost) and rejects anything else.
func LocalAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("local port is required")
	}
	if !strings.Contains(s, ":") {
		s = "localhost:" + s
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", fmt.Errorf("local address %q must be a port or host:port", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("local port must be between 1 and 65535")
	}
	for _, r := range host {
		if !(r == '.' || r == '-' || r == '_' || r == ':' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return "", fmt.Errorf("local host %q has characters that are not allowed", host)
		}
	}
	return net.JoinHostPort(host, portStr), nil
}

// OpenTunnel opens a tunnel on the current connection.
func (m *Manager) OpenTunnel(spec TunnelSpec) (TunnelView, error) {
	m.mu.Lock()
	c := m.cl
	m.mu.Unlock()
	if c == nil {
		return TunnelView{}, errors.New("not connected")
	}
	local, err := LocalAddress(spec.Local)
	if err != nil {
		return TunnelView{}, err
	}
	var opts []client.HTTPOption
	if spec.TTL != "" {
		d, err := time.ParseDuration(strings.TrimSpace(spec.TTL))
		if err != nil || d <= 0 {
			return TunnelView{}, fmt.Errorf("invalid auto-close time %q (use for example 30m or 2h)", spec.TTL)
		}
		opts = append(opts, client.WithTTL(d))
	}
	var t *client.Tunnel
	switch spec.Type {
	case "tcp":
		t, err = c.TCP(local, 0, opts...)
	case "http":
		opts, err = httpOptions(spec, opts)
		if err != nil {
			return TunnelView{}, err
		}
		t, err = c.HTTP(local, opts...)
	default:
		return TunnelView{}, fmt.Errorf("unknown tunnel type %q", spec.Type)
	}
	if err != nil {
		return TunnelView{}, err
	}
	v := TunnelView{ID: t.ID, Type: string(t.Type), URL: t.PublicURL, Port: t.Port, Local: t.LocalAddr}
	if !t.ExpiresAt.IsZero() {
		exp := t.ExpiresAt
		v.ExpiresAt = &exp
	}
	return v, nil
}

func httpOptions(spec TunnelSpec, opts []client.HTTPOption) ([]client.HTTPOption, error) {
	if sub := strings.ToLower(strings.TrimSpace(spec.Subdomain)); sub != "" {
		opts = append(opts, client.WithSubdomain(sub))
	}
	if d := strings.TrimSpace(spec.Domain); d != "" {
		opts = append(opts, client.WithCustomDomain(d))
	}
	if spec.Auth != "" {
		user, pass, ok := strings.Cut(spec.Auth, ":")
		if !ok || user == "" {
			return nil, errors.New("basic auth must be user:password")
		}
		opts = append(opts, client.WithAuth(user, pass))
	}
	if spec.PIN != "" {
		opts = append(opts, client.WithPIN(spec.PIN))
	}
	if allow := strings.TrimSpace(spec.Allow); allow != "" {
		var ips []string
		for _, ip := range strings.Split(allow, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				ips = append(ips, ip)
			}
		}
		opts = append(opts, client.WithAllowedIPs(ips))
	}
	if spec.Inspect {
		opts = append(opts, client.WithInspect())
	}
	return opts, nil
}

// CloseTunnel closes one tunnel.
func (m *Manager) CloseTunnel(id string) error {
	m.mu.Lock()
	c := m.cl
	m.mu.Unlock()
	if c == nil {
		return errors.New("not connected")
	}
	return c.CloseTunnel(id)
}

// record keeps an exchange (called by the client when one ends).
func (m *Manager) record(ex client.Exchange) {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	m.traffic = append(m.traffic, ex)
	if over := len(m.traffic) - trafficKeep; over > 0 {
		m.traffic = append([]client.Exchange(nil), m.traffic[over:]...)
	}
	m.stats.Requests++
	if ex.Error != "" || ex.Status >= 500 {
		m.stats.Errors++
	}
	m.stats.BytesIn += ex.BytesIn
	m.stats.BytesOut += ex.BytesOut
}

// Row is one line of the traffic table.
type Row struct {
	ID       uint64    `json:"id"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	Tunnel   string    `json:"tunnel"` // public address
	Remote   string    `json:"remote,omitempty"`
	Status   int       `json:"status,omitempty"`
	Millis   int64     `json:"ms"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Error    string    `json:"error,omitempty"`
}

func rowOf(ex client.Exchange) Row {
	return Row{ID: ex.ID, Time: ex.Time, Kind: ex.Kind, Method: ex.Method, Path: ex.Path, Tunnel: ex.TunnelURL, Remote: ex.Remote,
		Status: ex.Status, Millis: ex.Duration.Milliseconds(), BytesIn: ex.BytesIn, BytesOut: ex.BytesOut, Error: ex.Error}
}

// Traffic returns the rows with an ID above since (oldest first) and the
// newest ID seen.
func (m *Manager) Traffic(since uint64) (rows []Row, last uint64) {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	rows = []Row{}
	for _, ex := range m.traffic {
		if ex.ID > since {
			rows = append(rows, rowOf(ex))
		}
	}
	if n := len(m.traffic); n > 0 {
		last = m.traffic[n-1].ID
	}
	return rows, last
}

// ClearTraffic empties the log and the totals.
func (m *Manager) ClearTraffic() {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	m.traffic, m.stats = nil, Stats{}
}

func (m *Manager) find(id uint64) (client.Exchange, bool) {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	for _, ex := range m.traffic {
		if ex.ID == id {
			return ex, true
		}
	}
	return client.Exchange{}, false
}

// Message is one side of an exchange as the detail view shows it.
type Message struct {
	Headers   map[string][]string `json:"headers"`
	Body      string              `json:"body"`   // text, or "" for binary
	Binary    bool                `json:"binary"` // body is not text
	BodyBytes int                 `json:"body_bytes"`
	Truncated bool                `json:"truncated"`
}

// Detail is the full record of one exchange.
type Detail struct {
	Row
	LocalAddr string  `json:"local"`
	Host      string  `json:"host,omitempty"`
	Request   Message `json:"request"`
	Response  Message `json:"response"`
}

// Detail returns one exchange with headers and the captured bodies.
func (m *Manager) Detail(id uint64) (Detail, bool) {
	ex, ok := m.find(id)
	if !ok {
		return Detail{}, false
	}
	return Detail{
		Row: rowOf(ex), LocalAddr: ex.LocalAddr, Host: ex.Host,
		Request:  message(ex.ReqHeader, ex.ReqBody, ex.ReqTruncated),
		Response: message(ex.RespHeader, ex.RespBody, ex.RespTruncated),
	}, true
}

func message(h http.Header, body []byte, truncated bool) Message {
	msg := Message{Headers: map[string][]string(h), BodyBytes: len(body), Truncated: truncated}
	if msg.Headers == nil {
		msg.Headers = map[string][]string{}
	}
	if strings.EqualFold(h.Get("Content-Encoding"), "gzip") {
		if plain, ok := gunzipPrefix(body); ok {
			body = plain
		}
	}
	if isText(body) {
		msg.Body = string(body)
	} else {
		msg.Binary = len(body) > 0
	}
	return msg
}

// gunzipPrefix decodes as much of a (possibly cut-off) gzip body as it can.
func gunzipPrefix(b []byte) ([]byte, bool) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	plain, _ := io.ReadAll(io.LimitReader(zr, 4*captureBody))
	return plain, len(plain) > 0
}

// isText reports whether b is valid UTF-8 without control characters (other
// than whitespace), i.e. fit to show as text.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// ReplayResult is the answer of the local service to a replayed request.
type ReplayResult struct {
	Status    int     `json:"status"`
	Millis    int64   `json:"ms"`
	Response  Message `json:"response"`
	LocalAddr string  `json:"local"`
	Error     string  `json:"error,omitempty"`
}

var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Content-Length": true,
}

// Replay sends a captured HTTP request again, straight to the local service
// (not through the tunnel), and returns what it answers.
func (m *Manager) Replay(id uint64) (ReplayResult, error) {
	ex, ok := m.find(id)
	if !ok {
		return ReplayResult{}, errors.New("exchange not found")
	}
	if ex.Kind != "http" {
		return ReplayResult{}, errors.New("only HTTP requests can be replayed")
	}
	if ex.ReqTruncated {
		return ReplayResult{}, errors.New("the request body was longer than what is kept, so it cannot be replayed faithfully")
	}
	u := url.URL{Scheme: "http", Host: ex.LocalAddr}
	req, err := http.NewRequest(ex.Method, u.String()+ex.Path, bytes.NewReader(ex.ReqBody))
	if err != nil {
		return ReplayResult{}, fmt.Errorf("cannot rebuild the request: %w", err)
	}
	for k, vs := range ex.ReqHeader {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Host = ex.Host
	start := time.Now()
	hc := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	res := ReplayResult{LocalAddr: ex.LocalAddr, Millis: time.Since(start).Milliseconds()}
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, replayLimit+1))
	truncated := len(body) > replayLimit
	if truncated {
		body = body[:replayLimit]
	}
	res.Status = resp.StatusCode
	res.Response = message(resp.Header, body, truncated)
	return res, nil
}
