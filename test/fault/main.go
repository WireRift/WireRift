package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

const recoverySLO = 5 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fault suite failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	authManager := auth.NewManager("fault-suite-token")
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authManager
	cfg.OfflineGrace = 2 * time.Second
	srv := server.New(cfg, quiet)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "fault-ok")
	}))
	defer upstream.Close()

	proxy, err := newFaultProxy(srv.ControlAddr())
	if err != nil {
		return fmt.Errorf("start fault proxy: %w", err)
	}
	defer proxy.Close()

	clientConfig := client.DefaultConfig()
	clientConfig.ServerAddr = proxy.Addr()
	clientConfig.Token = authManager.DevToken()
	clientConfig.Reconnect = true
	clientConfig.ReconnectInterval = 50 * time.Millisecond
	clientConfig.MaxReconnectInterval = 200 * time.Millisecond
	clientConfig.HeartbeatInterval = 50 * time.Millisecond
	c := client.New(clientConfig, quiet)
	if err := c.Connect(); err != nil {
		return fmt.Errorf("connect original client: %w", err)
	}
	defer c.Close()

	localAddr := strings.TrimPrefix(upstream.URL, "http://")
	tunnel, err := c.HTTP(localAddr, client.WithSubdomain("fault-recovery"))
	if err != nil {
		return fmt.Errorf("create original tunnel: %w", err)
	}
	if err := waitHealthy(srv.HTTPAddr(), cfg.Domain, tunnel.Subdomain, 2*time.Second); err != nil {
		return fmt.Errorf("initial tunnel: %w", err)
	}

	proxy.SetLatency(25 * time.Millisecond)
	started := time.Now()
	if err := requestHealthy(srv.HTTPAddr(), cfg.Domain, tunnel.Subdomain); err != nil {
		return fmt.Errorf("latency injection request: %w", err)
	}
	latency := time.Since(started)
	proxy.SetLatency(0)
	if latency < 40*time.Millisecond {
		return fmt.Errorf("latency injection ineffective: round trip %s", latency)
	}
	fmt.Printf("FAULT_LATENCY_OK round_trip=%s\n", latency.Round(time.Millisecond))

	started = time.Now()
	proxy.DropConnections()
	if err := waitHealthy(srv.HTTPAddr(), cfg.Domain, tunnel.Subdomain, recoverySLO); err != nil {
		return fmt.Errorf("hard-drop recovery: %w", err)
	}
	if elapsed := time.Since(started); elapsed > recoverySLO {
		return fmt.Errorf("hard-drop recovery %s exceeds %s", elapsed, recoverySLO)
	} else {
		fmt.Printf("FAULT_DROP_RECOVERY_OK elapsed=%s\n", elapsed.Round(time.Millisecond))
	}

	started = time.Now()
	proxy.SetPartition(true)
	time.Sleep(400 * time.Millisecond)
	proxy.SetPartition(false)
	if err := waitHealthy(srv.HTTPAddr(), cfg.Domain, tunnel.Subdomain, recoverySLO); err != nil {
		return fmt.Errorf("partition recovery: %w", err)
	}
	if elapsed := time.Since(started); elapsed > recoverySLO {
		return fmt.Errorf("partition recovery %s exceeds %s", elapsed, recoverySLO)
	} else {
		fmt.Printf("FAULT_PARTITION_RECOVERY_OK elapsed=%s\n", elapsed.Round(time.Millisecond))
	}

	started = time.Now()
	proxy.SetBlackhole(true)
	time.Sleep(250 * time.Millisecond) // > three heartbeat intervals
	proxy.SetBlackhole(false)
	if err := waitHealthy(srv.HTTPAddr(), cfg.Domain, tunnel.Subdomain, recoverySLO); err != nil {
		return fmt.Errorf("half-open recovery: %w", err)
	}
	if elapsed := time.Since(started); elapsed > recoverySLO {
		return fmt.Errorf("half-open recovery %s exceeds %s", elapsed, recoverySLO)
	} else {
		fmt.Printf("FAULT_HALF_OPEN_RECOVERY_OK elapsed=%s\n", elapsed.Round(time.Millisecond))
	}

	if tunnel.Subdomain != "fault-recovery" {
		return fmt.Errorf("original tunnel identity changed to %q", tunnel.Subdomain)
	}
	fmt.Println("FAULT_SUITE_OK same_client=true same_tunnel=true")
	return nil
}

func requestHealthy(addr, domain, subdomain string) error {
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return err
	}
	req.Host = subdomain + "." + domain
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("read=%v close=%v", readErr, closeErr)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("fault-ok")) {
		return fmt.Errorf("status=%d body=%q", resp.StatusCode, body)
	}
	return nil
}

func waitHealthy(addr, domain, subdomain string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := requestHealthy(addr, domain, subdomain); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s: %v", timeout, lastErr)
}

type faultProxy struct {
	listener  net.Listener
	target    string
	latencyNS atomic.Int64
	partition atomic.Bool
	blackhole atomic.Bool
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[*proxiedConn]struct{}
}

type proxiedConn struct {
	client net.Conn
	target net.Conn
	done   chan struct{}
	once   sync.Once
}

func newFaultProxy(target string) (*faultProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &faultProxy{listener: listener, target: target, closed: make(chan struct{}), conns: make(map[*proxiedConn]struct{})}
	go p.acceptLoop()
	return p, nil
}

func (p *faultProxy) Addr() string { return p.listener.Addr().String() }

func (p *faultProxy) SetLatency(d time.Duration) { p.latencyNS.Store(int64(d)) }

func (p *faultProxy) SetBlackhole(enabled bool) { p.blackhole.Store(enabled) }

func (p *faultProxy) SetPartition(enabled bool) {
	p.partition.Store(enabled)
	if enabled {
		p.DropConnections()
	}
}

func (p *faultProxy) acceptLoop() {
	for {
		incoming, err := p.listener.Accept()
		if err != nil {
			return
		}
		if p.partition.Load() {
			_ = incoming.Close()
			continue
		}
		outgoing, err := net.DialTimeout("tcp", p.target, time.Second)
		if err != nil {
			_ = incoming.Close()
			continue
		}
		pc := &proxiedConn{client: incoming, target: outgoing, done: make(chan struct{})}
		p.mu.Lock()
		p.conns[pc] = struct{}{}
		p.mu.Unlock()
		go p.relay(pc, outgoing, incoming)
		go p.relay(pc, incoming, outgoing)
	}
}

func (p *faultProxy) relay(pc *proxiedConn, dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			for p.blackhole.Load() {
				select {
				case <-pc.done:
					return
				case <-p.closed:
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
			if delay := time.Duration(p.latencyNS.Load()); delay > 0 {
				time.Sleep(delay)
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				pc.close()
				p.remove(pc)
				return
			}
		}
		if err != nil {
			pc.close()
			p.remove(pc)
			return
		}
	}
}

func (pc *proxiedConn) close() {
	pc.once.Do(func() {
		close(pc.done)
		_ = pc.client.Close()
		_ = pc.target.Close()
	})
}

func (p *faultProxy) remove(pc *proxiedConn) {
	p.mu.Lock()
	delete(p.conns, pc)
	p.mu.Unlock()
}

func (p *faultProxy) DropConnections() {
	p.mu.Lock()
	connections := make([]*proxiedConn, 0, len(p.conns))
	for pc := range p.conns {
		connections = append(connections, pc)
	}
	p.mu.Unlock()
	for _, pc := range connections {
		pc.close()
		p.remove(pc)
	}
}

func (p *faultProxy) Close() {
	p.closeOnce.Do(func() {
		close(p.closed)
		_ = p.listener.Close()
		p.DropConnections()
	})
}
