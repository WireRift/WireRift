package server

import (
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
	"github.com/wirerift/wirerift/internal/utils"
)

// This file holds what the administrator view of the dashboard needs: a short
// in-memory event log, a rolling history of the main gauges and counters, a
// detailed snapshot, and a few management actions. With Config.StateFile the log and
// history survive a restart. Nothing here is reachable without the dashboard's authentication.

const (
	maxEvents       = 500
	maxHistory      = 360 // one hour at the default 10 s interval
	historyInterval = 10 * time.Second
)

// Event is one entry of the server's activity log.
type Event struct {
	ID      uint64    `json:"id"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info, warn
	Kind    string    `json:"kind"`  // session, tunnel, auth, server, admin
	Account string    `json:"account,omitempty"`
	Session string    `json:"session,omitempty"`
	Remote  string    `json:"remote,omitempty"`
	Message string    `json:"message"`
}

type eventLog struct {
	mu   sync.Mutex
	buf  []Event
	next uint64
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	e.ID = l.next
	e.Time = time.Now()
	if len(l.buf) >= maxEvents {
		copy(l.buf, l.buf[1:])
		l.buf = l.buf[:maxEvents-1]
	}
	l.buf = append(l.buf, e)
}

// recordEvent appends to the activity log.
func (s *Server) recordEvent(level, kind, account, session, remote, msg string) {
	s.events.add(Event{Level: level, Kind: kind, Account: account, Session: session, Remote: remote, Message: msg})
}

// Events returns the newest activity first, at most limit entries (0 = all
// kept), optionally restricted to one account ("" = every account).
func (s *Server) Events(limit int, account string) []Event {
	s.events.mu.Lock()
	defer s.events.mu.Unlock()
	out := make([]Event, 0, len(s.events.buf))
	for i := len(s.events.buf) - 1; i >= 0; i-- {
		e := s.events.buf[i]
		if account != "" && e.Account != account {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// HistoryPoint is one sample of the rolling history. Counters are cumulative:
// the reader takes differences between samples to get rates.
type HistoryPoint struct {
	T          int64   `json:"t"` // unix seconds
	Requests   uint64  `json:"requests"`
	Err4xx     uint64  `json:"err4xx"`
	Err5xx     uint64  `json:"err5xx"`
	BytesIn    int64   `json:"bytes_in"`
	BytesOut   int64   `json:"bytes_out"`
	Sessions   int     `json:"sessions"`
	Tunnels    int     `json:"tunnels"`
	HeapMB     float64 `json:"heap_mb"`
	Goroutines int     `json:"goroutines"`
	FDs        int     `json:"fds"`
}

type historyRing struct {
	mu  sync.Mutex
	buf []HistoryPoint
}

func (h *historyRing) add(p HistoryPoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buf) >= maxHistory {
		copy(h.buf, h.buf[1:])
		h.buf = h.buf[:maxHistory-1]
	}
	h.buf = append(h.buf, p)
}

// History returns the rolling samples, oldest first.
func (s *Server) History() []HistoryPoint {
	s.history.mu.Lock()
	defer s.history.mu.Unlock()
	return append([]HistoryPoint(nil), s.history.buf...)
}

func (s *Server) sampleHistory() HistoryPoint {
	sessions, httpT, tcpT := s.counts()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var requests uint64
	for i := range s.httpStatus {
		requests += s.httpStatus[i].Load()
	}
	return HistoryPoint{
		T: time.Now().Unix(), Requests: requests,
		Err4xx: s.httpStatus[3].Load(), Err5xx: s.httpStatus[4].Load(),
		BytesIn: s.bytesIn.Load(), BytesOut: s.bytesOut.Load(),
		Sessions: sessions, Tunnels: httpT + tcpT,
		HeapMB: float64(ms.HeapAlloc) / (1 << 20), Goroutines: runtime.NumGoroutine(), FDs: openFDs(),
	}
}

// runHistory samples until the server stops.
func (s *Server) runHistory() {
	defer s.wg.Done()
	t := time.NewTicker(historyInterval)
	defer t.Stop()
	for n := 1; ; n++ {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.history.add(s.sampleHistory())
			if n%stateSaveEvery == 0 {
				s.saveState()
			}
		}
	}
}

// counts returns the live session count and HTTP/TCP tunnel counts.
func (s *Server) counts() (sessions, httpTunnels, tcpTunnels int) {
	s.sessions.Range(func(_, _ any) bool { sessions++; return true })
	s.tunnels.Range(func(key, value any) bool {
		if isAliasKey(key) {
			return true
		}
		if t, ok := value.(*Tunnel); ok {
			switch t.Type {
			case proto.TunnelTypeHTTP:
				httpTunnels++
			case proto.TunnelTypeTCP:
				tcpTunnels++
			}
		}
		return true
	})
	return
}

// openFDs is the number of open file descriptors of this process (-1 where
// /proc is not available).
func openFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// HeldInfo is a subdomain reserved for an account whose client dropped.
type HeldInfo struct {
	Subdomain string    `json:"subdomain"`
	Account   string    `json:"account"`
	Until     time.Time `json:"until"`
}

// AccountUsage is what one account currently uses.
type AccountUsage struct {
	Account  string `json:"account"`
	Sessions int    `json:"sessions"`
	Tunnels  int    `json:"tunnels"`
}

// LatencyBucket is one cumulative bucket of the request-duration histogram.
type LatencyBucket struct {
	LeMs  float64 `json:"le_ms"` // 0 = +Inf
	Count uint64  `json:"count"`
}

// AdminOverview is the detailed server snapshot behind the admin dashboard.
type AdminOverview struct {
	Version       string    `json:"version"`
	GoVersion     string    `json:"go_version"`
	Domain        string    `json:"domain"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds float64   `json:"uptime_seconds"`
	Ready         bool      `json:"ready"`

	Sessions    int `json:"sessions"`
	HTTPTunnels int `json:"http_tunnels"`
	TCPTunnels  int `json:"tcp_tunnels"`
	TCPPortsUse int `json:"tcp_ports_in_use"`
	TCPPortsMax int `json:"tcp_ports_total"`

	BytesIn  int64             `json:"bytes_in"`
	BytesOut int64             `json:"bytes_out"`
	Requests uint64            `json:"requests"`
	Status   map[string]uint64 `json:"status"`

	AvgLatencyMs float64         `json:"avg_latency_ms"`
	P50Ms        float64         `json:"p50_ms"`
	P95Ms        float64         `json:"p95_ms"`
	P99Ms        float64         `json:"p99_ms"`
	Latency      []LatencyBucket `json:"latency_buckets"`

	Goroutines int     `json:"goroutines"`
	HeapMB     float64 `json:"heap_mb"`
	SysMB      float64 `json:"sys_mb"`
	NumGC      uint32  `json:"num_gc"`
	GCPauseMs  float64 `json:"gc_pause_total_ms"`
	CPUs       int     `json:"cpus"`
	OpenFDs    int     `json:"open_fds"`

	CertExpiry        *time.Time `json:"cert_expiry,omitempty"`
	PersistenceErrors uint64     `json:"persistence_errors"`

	EdgeRate       float64 `json:"edge_rate_per_ip"`
	EdgeBurst      int     `json:"edge_burst"`
	TrustedProxies int     `json:"trusted_proxy_cidrs"`
	OfflineGrace   float64 `json:"offline_grace_seconds"`
	DashboardHost  string  `json:"dashboard_host,omitempty"`

	Held     []HeldInfo     `json:"held_subdomains"`
	Accounts []AccountUsage `json:"account_usage"`
}

// AdminOverview builds the snapshot.
func (s *Server) AdminOverview() AdminOverview {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	sessions, httpT, tcpT := s.counts()

	o := AdminOverview{
		Version: s.config.Version, GoVersion: runtime.Version(), Domain: s.config.Domain,
		StartedAt: s.startTime, Ready: s.ready.Load(),
		Sessions: sessions, HTTPTunnels: httpT, TCPTunnels: tcpT,
		TCPPortsMax: s.tcpPortEnd - s.tcpPortStart + 1,
		BytesIn:     s.bytesIn.Load(), BytesOut: s.bytesOut.Load(),
		Status:     map[string]uint64{},
		Goroutines: runtime.NumGoroutine(), HeapMB: float64(ms.HeapAlloc) / (1 << 20), SysMB: float64(ms.Sys) / (1 << 20),
		NumGC: ms.NumGC, GCPauseMs: float64(ms.PauseTotalNs) / 1e6, CPUs: runtime.NumCPU(), OpenFDs: openFDs(),
		PersistenceErrors: s.persistenceErrors.Load(),
		EdgeRate:          edgeRate(s.config.EdgeRatePerIP, 100), EdgeBurst: int(edgeRate(float64(s.config.EdgeRateBurst), 50)),
		TrustedProxies: len(s.trustedProxyNets), OfflineGrace: s.config.OfflineGrace.Seconds(),
		Held: []HeldInfo{}, Accounts: []AccountUsage{},
	}
	if !s.startTime.IsZero() {
		o.UptimeSeconds = time.Since(s.startTime).Seconds()
	}
	if s.config.PersistenceErrors != nil {
		o.PersistenceErrors += s.config.PersistenceErrors()
	}
	if s.config.CertificateExpiry != nil {
		if e := s.config.CertificateExpiry(); !e.IsZero() {
			o.CertExpiry = &e
		}
	}
	if dh := s.dashboardRoute.Load(); dh != nil {
		o.DashboardHost = dh.host
	}
	s.tcpPorts.Range(func(_, _ any) bool { o.TCPPortsUse++; return true })

	for i := range s.httpStatus {
		n := s.httpStatus[i].Load()
		o.Requests += n
		o.Status[string(rune('1'+i))+"xx"] = n
	}
	o.AvgLatencyMs, o.P50Ms, o.P95Ms, o.P99Ms, o.Latency = s.latencySummary(o.Requests)

	s.held.Range(func(k, v any) bool {
		if h, ok := v.(heldName); ok && time.Now().Before(h.until) {
			sub, _ := k.(string)
			o.Held = append(o.Held, HeldInfo{Subdomain: sub, Account: h.accountID, Until: h.until})
		}
		return true
	})
	sort.Slice(o.Held, func(i, j int) bool { return o.Held[i].Subdomain < o.Held[j].Subdomain })

	usage := map[string]*AccountUsage{}
	get := func(id string) *AccountUsage {
		if usage[id] == nil {
			usage[id] = &AccountUsage{Account: id}
		}
		return usage[id]
	}
	s.sessions.Range(func(_, v any) bool {
		if sess, ok := v.(*Session); ok {
			get(sess.AccountID).Sessions++
		}
		return true
	})
	s.tunnels.Range(func(key, v any) bool {
		if isAliasKey(key) {
			return true
		}
		if t, ok := v.(*Tunnel); ok {
			get(t.AccountID).Tunnels++
		}
		return true
	})
	for _, u := range usage {
		o.Accounts = append(o.Accounts, *u)
	}
	sort.Slice(o.Accounts, func(i, j int) bool { return o.Accounts[i].Account < o.Accounts[j].Account })
	return o
}

// latencySummary derives average and bucket-bound percentiles (the upper bound
// of the bucket the percentile falls into) from the request-duration histogram.
func (s *Server) latencySummary(total uint64) (avg, p50, p95, p99 float64, buckets []LatencyBucket) {
	if total > 0 {
		avg = float64(s.httpDurationNanos.Load()) / float64(total) / 1e6
	}
	var cum uint64
	counts := make([]uint64, len(httpDurationBounds)+1)
	for i := range counts {
		counts[i] = s.httpDurationBuckets[i].Load()
	}
	var sum uint64
	for _, c := range counts {
		sum += c
	}
	pick := func(q float64) float64 {
		if sum == 0 {
			return 0
		}
		target := uint64(float64(sum) * q)
		var c uint64
		for i, n := range counts {
			c += n
			if c > target || (c == sum && c >= target) {
				if i < len(httpDurationBounds) {
					return httpDurationBounds[i] * 1000
				}
				return httpDurationBounds[len(httpDurationBounds)-1] * 1000
			}
		}
		return 0
	}
	p50, p95, p99 = pick(0.50), pick(0.95), pick(0.99)
	for i, b := range httpDurationBounds {
		cum += counts[i]
		buckets = append(buckets, LatencyBucket{LeMs: b * 1000, Count: cum})
	}
	cum += counts[len(httpDurationBounds)]
	buckets = append(buckets, LatencyBucket{LeMs: 0, Count: cum})
	return
}

// KickSession disconnects a client session. The client may reconnect on its
// own; to keep it out, revoke its token. It reports whether the session exists.
func (s *Server) KickSession(id, by string) bool {
	v, ok := s.sessions.Load(id)
	if !ok {
		return false
	}
	sess := v.(*Session)
	s.recordEvent("warn", "admin", sess.AccountID, sess.ID, "", "session disconnected by administrator "+by)
	if sess.Mux != nil {
		sess.Mux.Close()
	}
	return true
}

// RecordAdminEvent logs an administrator's action (token created or revoked,
// for example) in the activity log. msg must not contain secrets.
func (s *Server) RecordAdminEvent(by, msg string) {
	s.recordEvent("info", "admin", "", "", "", msg+" by "+by)
}

// dashboardRoute serves the dashboard on a host of the HTTP(S) edge.
type dashboardRoute struct {
	host    string
	handler http.Handler
}

// SetDashboardRoute publishes handler on the full host name (for example
// "dashboard.tunnel.example.com") of the edge. Plain-HTTP requests are
// redirected to HTTPS once an HTTPS edge is configured. Pass "" to unpublish.
func (s *Server) SetDashboardRoute(host string, handler http.Handler) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || handler == nil {
		s.dashboardRoute.Store(nil)
		return
	}
	s.dashboardRoute.Store(&dashboardRoute{host: host, handler: handler})
}

func (s *Server) isDashboardHost(host string) bool {
	r := s.dashboardRoute.Load()
	return r != nil && normalizeHostHeader(host) == r.host
}

// serveDashboardHost handles a request whose Host is the published dashboard
// host. It reports false when the request is for something else.
func (s *Server) serveDashboardHost(w http.ResponseWriter, r *http.Request) bool {
	route := s.dashboardRoute.Load()
	if route == nil || normalizeHostHeader(r.Host) != route.host {
		return false
	}
	clientIP := s.clientIP(r)
	if !s.rateLimiter.Allow(clientIP) {
		writeEdgeError(w, r, http.StatusTooManyRequests, "Rate limit exceeded")
		return true
	}
	if r.TLS == nil && s.config.TLSConfig != nil {
		target := "https://" + route.host
		if p := s.config.PublicPort; p != 0 && p != 443 {
			target = "https://" + net.JoinHostPort(route.host, strconv.Itoa(p))
		}
		// The host is the configured dashboard host, never taken from the request.
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusPermanentRedirect) //nolint:gosec // G710: fixed, configured host
		return true
	}
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	w.Header().Set("Cache-Control", "no-store")
	// The dashboard's brute-force guard keys on RemoteAddr: give it the visitor,
	// not the edge's socket peer (they differ behind a trusted proxy).
	r2 := r.Clone(r.Context())
	r2.RemoteAddr = net.JoinHostPort(clientIP, "0")
	route.handler.ServeHTTP(w, r2)
	return true
}

// ConnectInfo is what a person needs to point a client at this server: the
// dashboard's Connect page builds ready-to-run commands from it.
type ConnectInfo struct {
	Version      string   `json:"version"`
	Domain       string   `json:"domain"`
	ControlHost  string   `json:"control_host"`
	ControlPort  int      `json:"control_port"`
	ControlTLS   bool     `json:"control_tls"`
	ServerArg    string   `json:"server_arg"` // the value for the client's -server flag
	PublicScheme string   `json:"public_scheme"`
	PublicPort   int      `json:"public_port"`
	TCPPortStart int      `json:"tcp_port_start"`
	TCPPortEnd   int      `json:"tcp_port_end"`
	Reserved     []string `json:"reserved_subdomains"`
}

// ConnectInfo describes how clients reach this server.
func (s *Server) ConnectInfo() ConnectInfo {
	info := ConnectInfo{
		Version:      s.config.Version,
		Domain:       s.config.Domain,
		ControlHost:  s.config.Domain,
		ControlTLS:   s.config.ControlTLSConfig != nil,
		PublicScheme: s.config.PublicScheme,
		PublicPort:   s.config.PublicPort,
		TCPPortStart: s.tcpPortStart,
		TCPPortEnd:   s.tcpPortEnd,
		Reserved:     utils.ReservedSubdomains(),
	}
	if info.PublicScheme == "" {
		info.PublicScheme = "http"
	}
	if _, port, err := net.SplitHostPort(s.ControlAddr()); err == nil {
		info.ControlPort, _ = strconv.Atoi(port)
	}
	info.ServerArg = net.JoinHostPort(info.ControlHost, strconv.Itoa(info.ControlPort))
	if info.ControlTLS {
		info.ServerArg = "tls://" + info.ServerArg
	}
	return info
}
