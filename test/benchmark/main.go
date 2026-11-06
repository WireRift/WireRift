package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║         WireRift Benchmark Suite             ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()

	// Setup: local service + server + client + tunnel
	env, err := setup()
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	defer env.cleanup()

	fmt.Printf("  Server:  %s\n", env.srv.ControlAddr())
	fmt.Printf("  HTTP:    %s\n", env.srv.HTTPAddr())
	fmt.Printf("  Tunnel:  %s\n", env.tunnel.PublicURL)
	fmt.Printf("  Local:   %s\n", env.localAddr)
	fmt.Println()

	// Benchmarks
	for _, bench := range []func(*benchEnv) error{
		benchHealthz,
		benchHTTPLatency,
		benchHTTPThroughput,
		benchHTTPConcurrency,
		benchTCPThroughput,
		benchTunnelCreation,
	} {
		if err := bench(env); err != nil {
			return err
		}
	}

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║              Benchmark Complete              ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	return nil
}

type benchEnv struct {
	srv       *server.Server
	client    *client.Client
	authMgr   *auth.Manager
	tunnel    *client.Tunnel
	tcpTunnel *client.Tunnel
	localAddr string
	domain    string
	httpBase  string
	cleanup   func()
	visitorID atomic.Uint64
	quick     bool
}

func setup() (*benchEnv, error) {
	// Local HTTP service
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/1k", func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024))
	})
	mux.HandleFunc("/64k", func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 64*1024))
	})
	mux.HandleFunc("/1m", func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024*1024))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for local HTTP service: %w", err)
	}
	localServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := localServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "benchmark local service failed: %v\n", err)
		}
	}()

	// Server
	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.TCPAddrRange = "30000-30100"
	cfg.AuthManager = authMgr
	cfg.MaxTunnelsPerSession = 100
	// Capacity uses a bounded pool of synthetic RFC 2544 visitor addresses.
	// Production's per-visitor abuse limit remains enabled and unchanged.
	cfg.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, quiet)
	if err := srv.Start(); err != nil {
		_ = localServer.Close()
		return nil, fmt.Errorf("start server: %w", err)
	}

	// Client
	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, quiet)
	if err := c.Connect(); err != nil {
		_ = srv.Stop()
		_ = localServer.Close()
		return nil, fmt.Errorf("connect client: %w", err)
	}

	// HTTP tunnel
	t, err := c.HTTP(ln.Addr().String(), client.WithSubdomain("bench"))
	if err != nil {
		_ = c.Close()
		_ = srv.Stop()
		_ = localServer.Close()
		return nil, fmt.Errorf("create HTTP tunnel: %w", err)
	}

	// TCP tunnel
	tcpT, err := c.TCP(ln.Addr().String(), 0)
	if err != nil {
		_ = c.Close()
		_ = srv.Stop()
		_ = localServer.Close()
		return nil, fmt.Errorf("create TCP tunnel: %w", err)
	}

	return &benchEnv{
		srv:       srv,
		client:    c,
		authMgr:   authMgr,
		tunnel:    t,
		tcpTunnel: tcpT,
		localAddr: ln.Addr().String(),
		domain:    cfg.Domain,
		httpBase:  "http://" + srv.HTTPAddr(),
		quick:     os.Getenv("WIRERIFT_BENCH_QUICK") == "1",
		cleanup: func() {
			_ = c.Close()
			_ = srv.Stop()
			_ = localServer.Close()
		},
	}, nil
}

func (env *benchEnv) tunneledRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, env.httpBase+path, body)
	if err != nil {
		return nil, err
	}
	req.Host = "bench." + env.domain
	// 198.18.0.0/15 is reserved for benchmark tests. Reuse a fixed pool so the
	// rate-limiter map is bounded while each synthetic visitor stays below the
	// production per-IP threshold.
	id := env.visitorID.Add(1) % 4096
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.18.%d.%d", id/256, id%256))
	return req, nil
}

func benchHealthz(env *benchEnv) error {
	fmt.Println("── Healthz Endpoint Latency ──────────────────")

	hc := &http.Client{Timeout: 5 * time.Second}
	samples := 1000
	if env.quick {
		samples = 20
	}
	latencies := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		resp, err := hc.Get(env.httpBase + "/healthz")
		if err != nil {
			return fmt.Errorf("healthz request %d: %w", i, err)
		}
		_, copyErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz request %d: status=%d copy=%v close=%v", i, resp.StatusCode, copyErr, closeErr)
		}
		latencies = append(latencies, time.Since(start))
	}
	avg := avgDuration(latencies)
	p50 := percentile(latencies, 50)
	p99 := percentile(latencies, 99)
	fmt.Printf("  %d requests:  avg=%-10s p50=%-10s p99=%-10s\n", samples, avg, p50, p99)
	fmt.Println()
	return nil
}

func benchHTTPLatency(env *benchEnv) error {
	fmt.Println("── HTTP Latency (single request round-trip) ──")

	hc := &http.Client{Timeout: 10 * time.Second}
	sizes := []struct {
		name string
		path string
	}{
		{"2B response", "/small"},
		{"1KB response", "/1k"},
		{"64KB response", "/64k"},
		{"1MB response", "/1m"},
	}

	// Direct baseline
	fmt.Println()
	fmt.Println("  Direct (no tunnel):")
	samples := 100
	if env.quick {
		samples = 10
	}
	directP95 := make(map[string]time.Duration, len(sizes))
	for _, s := range sizes {
		latencies := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			start := time.Now()
			resp, err := hc.Get("http://" + env.localAddr + s.path)
			if err != nil {
				return fmt.Errorf("direct latency %s request %d: %w", s.name, i, err)
			}
			_, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
				return fmt.Errorf("direct latency %s request %d: status=%d copy=%v close=%v", s.name, i, resp.StatusCode, copyErr, closeErr)
			}
			latencies = append(latencies, time.Since(start))
		}
		avg := avgDuration(latencies)
		p50 := percentile(latencies, 50)
		p95 := percentile(latencies, 95)
		p99 := percentile(latencies, 99)
		directP95[s.path] = p95
		fmt.Printf("    %-16s avg=%-10s p50=%-10s p95=%-10s p99=%-10s\n", s.name, avg, p50, p95, p99)
	}

	// Through tunnel
	fmt.Println()
	fmt.Println("  Through tunnel:")
	for _, s := range sizes {
		latencies := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			req, err := env.tunneledRequest(http.MethodGet, s.path, nil)
			if err != nil {
				return fmt.Errorf("build tunneled latency request: %w", err)
			}
			start := time.Now()
			resp, err := hc.Do(req)
			if err != nil {
				return fmt.Errorf("tunneled latency %s request %d: %w", s.name, i, err)
			}
			_, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
				return fmt.Errorf("tunneled latency %s request %d: status=%d copy=%v close=%v", s.name, i, resp.StatusCode, copyErr, closeErr)
			}
			latencies = append(latencies, time.Since(start))
		}
		avg := avgDuration(latencies)
		p50 := percentile(latencies, 50)
		p95 := percentile(latencies, 95)
		p99 := percentile(latencies, 99)
		overheadP95 := p95 - directP95[s.path]
		if overheadP95 < 0 {
			overheadP95 = 0
		}
		fmt.Printf("    %-16s avg=%-10s p50=%-10s p95=%-10s p99=%-10s overhead_p95=%s\n",
			s.name, avg, p50, p95, p99, overheadP95.Round(time.Microsecond))
	}
	fmt.Println()
	return nil
}

func benchHTTPThroughput(env *benchEnv) error {
	fmt.Println("── HTTP Throughput (sustained transfer) ──────")

	hc := &http.Client{Timeout: 30 * time.Second}
	duration := 3 * time.Second
	if env.quick {
		duration = 300 * time.Millisecond
	}

	// Upload throughput
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("generate throughput payload: %w", err)
	}

	var uploaded int64
	start := time.Now()
	for time.Since(start) < duration {
		req, err := env.tunneledRequest(http.MethodPost, "/echo",
			io.LimitReader(newRepeatReader(payload), 1<<20))
		if err != nil {
			return fmt.Errorf("build upload request: %w", err)
		}
		req.ContentLength = 1 << 20
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("upload request: %w", err)
		}
		n, copyErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
			return fmt.Errorf("upload response: status=%d copy=%v close=%v", resp.StatusCode, copyErr, closeErr)
		}
		uploaded += n
	}
	uploadElapsed := time.Since(start)
	uploadMBps := float64(uploaded) / uploadElapsed.Seconds() / 1024 / 1024

	// Download throughput
	var downloaded int64
	start = time.Now()
	for time.Since(start) < duration {
		req, err := env.tunneledRequest(http.MethodGet, "/1m", nil)
		if err != nil {
			return fmt.Errorf("build download request: %w", err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("download request: %w", err)
		}
		n, copyErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download response: status=%d copy=%v close=%v", resp.StatusCode, copyErr, closeErr)
		}
		downloaded += n
	}
	downloadElapsed := time.Since(start)
	downloadMBps := float64(downloaded) / downloadElapsed.Seconds() / 1024 / 1024

	fmt.Printf("  Upload:   %.1f MB/s (%.0f Mbps; %.1f MB in %s)\n", uploadMBps, uploadMBps*8, float64(uploaded)/1024/1024, uploadElapsed.Round(time.Millisecond))
	fmt.Printf("  Download: %.1f MB/s (%.0f Mbps; %.1f MB in %s)\n", downloadMBps, downloadMBps*8, float64(downloaded)/1024/1024, downloadElapsed.Round(time.Millisecond))
	fmt.Println()
	return nil
}

func benchHTTPConcurrency(env *benchEnv) error {
	fmt.Println("── HTTP Concurrency (parallel requests) ──────")

	concurrencies := []int{1, 10, 50}
	if env.quick {
		concurrencies = []int{1, 10}
	}

	// Shared HTTP client with connection pool to avoid thread exhaustion on Windows
	sharedClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	defer sharedClient.CloseIdleConnections()

	for _, conc := range concurrencies {
		var successful atomic.Int64
		var rejected atomic.Int64
		var transportErrors atomic.Int64
		var latencyMu sync.Mutex
		latencies := make([]time.Duration, 0, conc*100)

		duration := 3 * time.Second
		if env.quick {
			duration = 300 * time.Millisecond
		}
		start := time.Now()
		var wg sync.WaitGroup

		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Since(start) < duration {
					req, err := env.tunneledRequest(http.MethodGet, "/small", nil)
					if err != nil {
						transportErrors.Add(1)
						continue
					}
					t0 := time.Now()
					resp, err := sharedClient.Do(req)
					if err != nil {
						transportErrors.Add(1)
						continue
					}
					_, copyErr := io.Copy(io.Discard, resp.Body)
					closeErr := resp.Body.Close()
					if copyErr != nil || closeErr != nil {
						transportErrors.Add(1)
						continue
					}
					if !successfulStatus(resp.StatusCode) {
						rejected.Add(1)
						continue
					}
					latency := time.Since(t0)
					latencyMu.Lock()
					latencies = append(latencies, latency)
					latencyMu.Unlock()
					successful.Add(1)
				}
			}()
		}
		wg.Wait()

		elapsed := time.Since(start)
		rps := float64(successful.Load()) / elapsed.Seconds()
		if successful.Load() == 0 || rejected.Load() > 0 || transportErrors.Load() > 0 {
			return fmt.Errorf("concurrency %d produced success=%d rejected=%d transport_errors=%d",
				conc, successful.Load(), rejected.Load(), transportErrors.Load())
		}

		fmt.Printf("  %3d concurrent:  %6.0f successful req/s  avg=%-10s p95=%-10s p99=%-10s rejected=0 errors=0\n",
			conc, rps, avgDuration(latencies), percentile(latencies, 95), percentile(latencies, 99))
	}
	fmt.Println()
	return nil
}

func benchTCPThroughput(env *benchEnv) error {
	fmt.Println("── TCP Tunnel Throughput ──────────────────────")

	// Connect through TCP tunnel port
	port := env.tcpTunnel.Port
	if port == 0 {
		return fmt.Errorf("TCP tunnel has no assigned port")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect TCP tunnel: %w", err)
	}
	defer conn.Close()

	// Send HTTP request through raw TCP tunnel
	req := "GET /1m HTTP/1.1\r\nHost: localhost\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("write TCP request: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("set TCP read deadline: %w", err)
	}
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return fmt.Errorf("read TCP response headers: %w", err)
	}
	n, copyErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	elapsed := time.Since(start)
	if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK || n != 1<<20 {
		return fmt.Errorf("TCP response: status=%d bytes=%d copy=%v close=%v", resp.StatusCode, n, copyErr, closeErr)
	}
	mbps := float64(n) / elapsed.Seconds() / 1024 / 1024
	fmt.Printf("  Download: %.1f MB/s (%.0f Mbps; %d bytes in %s)\n", mbps, mbps*8, n, elapsed.Round(time.Millisecond))
	fmt.Println()
	return nil
}

func benchTunnelCreation(env *benchEnv) error {
	fmt.Println("── Tunnel Creation Speed ─────────────────────")

	count := 50
	if env.quick {
		count = 5
	}
	succeeded := 0
	latencies := make([]time.Duration, 0, count)
	start := time.Now()
	for i := 0; i < count; i++ {
		requestStart := time.Now()
		t, err := env.client.HTTP(env.localAddr, client.WithSubdomain(fmt.Sprintf("benchcreate%d", i)))
		if err != nil {
			return fmt.Errorf("create tunnel %d after %d successes: %w", i, succeeded, err)
		}
		_ = t
		latencies = append(latencies, time.Since(requestStart))
		succeeded++
	}
	elapsed := time.Since(start)
	rate := float64(succeeded) / elapsed.Seconds()

	fmt.Printf("  %d tunnels in %s (%.0f tunnels/sec, avg=%s p95=%s p99=%s)\n",
		succeeded, elapsed.Round(time.Millisecond), rate, avgDuration(latencies), percentile(latencies, 95), percentile(latencies, 99))
	fmt.Println()
	return nil
}

func successfulStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// Helpers

type repeatReader struct {
	data []byte
}

func newRepeatReader(data []byte) *repeatReader {
	return &repeatReader{data: data}
}

func (r *repeatReader) Read(p []byte) (int, error) {
	return copy(p, r.data), nil
}

func avgDuration(ds []time.Duration) time.Duration {
	var total time.Duration
	count := 0
	for _, d := range ds {
		if d > 0 {
			total += d
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return (total / time.Duration(count)).Round(time.Microsecond)
}

func percentile(ds []time.Duration, pct int) time.Duration {
	var valid []time.Duration
	for _, d := range ds {
		if d > 0 {
			valid = append(valid, d)
		}
	}
	if len(valid) == 0 {
		return 0
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i] < valid[j] })
	idx := len(valid) * pct / 100
	if idx >= len(valid) {
		idx = len(valid) - 1
	}
	return valid[idx].Round(time.Microsecond)
}
