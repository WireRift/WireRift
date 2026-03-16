package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║         WireRift Benchmark Suite             ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()

	// Setup: local service + server + client + tunnel
	env := setup()
	defer env.cleanup()

	fmt.Printf("  Server:  %s\n", env.srv.ControlAddr())
	fmt.Printf("  HTTP:    %s\n", env.srv.HTTPAddr())
	fmt.Printf("  Tunnel:  %s\n", env.tunnel.PublicURL)
	fmt.Printf("  Local:   %s\n", env.localAddr)
	fmt.Println()

	// Benchmarks
	benchHealthz(env)
	benchHTTPLatency(env)
	benchHTTPThroughput(env)
	benchHTTPConcurrency(env)
	benchTCPThroughput(env)
	benchTunnelCreation(env)

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║              Benchmark Complete              ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
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
}

func setup() *benchEnv {
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

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(ln, mux)

	// Server
	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.TCPAddrRange = "30000-30100"
	cfg.AuthManager = authMgr
	cfg.MaxTunnelsPerSession = 100
	srv := server.New(cfg, nil)
	srv.Start()

	// Client
	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	c.Connect()

	// HTTP tunnel
	t, _ := c.HTTP(ln.Addr().String(), client.WithSubdomain("bench"))

	// TCP tunnel
	tcpT, _ := c.TCP(ln.Addr().String(), 0)

	time.Sleep(100 * time.Millisecond)

	return &benchEnv{
		srv:       srv,
		client:    c,
		authMgr:   authMgr,
		tunnel:    t,
		tcpTunnel: tcpT,
		localAddr: ln.Addr().String(),
		domain:    cfg.Domain,
		httpBase:  "http://" + srv.HTTPAddr(),
		cleanup: func() {
			c.Close()
			srv.Stop()
			ln.Close()
		},
	}
}

func benchHealthz(env *benchEnv) {
	fmt.Println("── Healthz Endpoint Latency ──────────────────")

	hc := &http.Client{Timeout: 5 * time.Second}
	latencies := make([]time.Duration, 1000)
	for i := 0; i < 1000; i++ {
		start := time.Now()
		resp, err := hc.Get(env.httpBase + "/healthz")
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		latencies[i] = time.Since(start)
	}
	avg := avgDuration(latencies)
	p50 := percentile(latencies, 50)
	p99 := percentile(latencies, 99)
	fmt.Printf("  1000 requests:  avg=%-10s p50=%-10s p99=%-10s\n", avg, p50, p99)
	fmt.Println()
}

func benchHTTPLatency(env *benchEnv) {
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
	for _, s := range sizes {
		latencies := make([]time.Duration, 100)
		for i := 0; i < 100; i++ {
			start := time.Now()
			resp, err := hc.Get("http://" + env.localAddr + s.path)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			latencies[i] = time.Since(start)
		}
		avg := avgDuration(latencies)
		p50 := percentile(latencies, 50)
		p99 := percentile(latencies, 99)
		fmt.Printf("    %-16s avg=%-10s p50=%-10s p99=%-10s\n", s.name, avg, p50, p99)
	}

	// Through tunnel
	fmt.Println()
	fmt.Println("  Through tunnel:")
	for _, s := range sizes {
		latencies := make([]time.Duration, 100)
		for i := 0; i < 100; i++ {
			req, _ := http.NewRequest("GET", env.httpBase+s.path, nil)
			req.Host = "bench." + env.domain
			start := time.Now()
			resp, err := hc.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			latencies[i] = time.Since(start)
		}
		avg := avgDuration(latencies)
		p50 := percentile(latencies, 50)
		p99 := percentile(latencies, 99)
		fmt.Printf("    %-16s avg=%-10s p50=%-10s p99=%-10s\n", s.name, avg, p50, p99)
	}
	fmt.Println()
}

func benchHTTPThroughput(env *benchEnv) {
	fmt.Println("── HTTP Throughput (sustained transfer) ──────")

	hc := &http.Client{Timeout: 30 * time.Second}
	duration := 3 * time.Second

	// Upload throughput
	payload := make([]byte, 64*1024)
	rand.Read(payload)

	var uploaded int64
	start := time.Now()
	for time.Since(start) < duration {
		req, _ := http.NewRequest("POST", env.httpBase+"/echo", io.NopCloser(
			io.LimitReader(newRepeatReader(payload), 64*1024),
		))
		req.Host = "bench." + env.domain
		req.ContentLength = 64 * 1024
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		uploaded += n
	}
	elapsed := time.Since(start)
	uploadMBps := float64(uploaded) / elapsed.Seconds() / 1024 / 1024

	// Download throughput
	var downloaded int64
	start = time.Now()
	for time.Since(start) < duration {
		req, _ := http.NewRequest("GET", env.httpBase+"/1m", nil)
		req.Host = "bench." + env.domain
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		downloaded += n
	}
	elapsed = time.Since(start)
	downloadMBps := float64(downloaded) / elapsed.Seconds() / 1024 / 1024

	fmt.Printf("  Upload:   %.1f MB/s (%.1f MB in %s)\n", uploadMBps, float64(uploaded)/1024/1024, elapsed.Round(time.Millisecond))
	fmt.Printf("  Download: %.1f MB/s (%.1f MB in %s)\n", downloadMBps, float64(downloaded)/1024/1024, elapsed.Round(time.Millisecond))
	fmt.Println()
}

func benchHTTPConcurrency(env *benchEnv) {
	fmt.Println("── HTTP Concurrency (parallel requests) ──────")

	concurrencies := []int{1, 10, 50, 100}

	for _, conc := range concurrencies {
		var totalRequests int64
		var totalErrors int64
		var totalLatency int64

		duration := 3 * time.Second
		start := time.Now()
		var wg sync.WaitGroup

		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hc := &http.Client{Timeout: 5 * time.Second}
				for time.Since(start) < duration {
					req, _ := http.NewRequest("GET", env.httpBase+"/small", nil)
					req.Host = "bench." + env.domain
					t0 := time.Now()
					resp, err := hc.Do(req)
					if err != nil {
						atomic.AddInt64(&totalErrors, 1)
						continue
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					atomic.AddInt64(&totalLatency, int64(time.Since(t0)))
					atomic.AddInt64(&totalRequests, 1)
				}
			}()
		}
		wg.Wait()

		elapsed := time.Since(start)
		rps := float64(totalRequests) / elapsed.Seconds()
		avgLat := time.Duration(0)
		if totalRequests > 0 {
			avgLat = time.Duration(totalLatency / totalRequests)
		}

		fmt.Printf("  %3d concurrent:  %6.0f req/s  avg_latency=%-10s  errors=%d\n",
			conc, rps, avgLat.Round(time.Microsecond), totalErrors)
	}
	fmt.Println()
}

func benchTCPThroughput(env *benchEnv) {
	fmt.Println("── TCP Tunnel Throughput ──────────────────────")

	// Connect through TCP tunnel port
	port := env.tcpTunnel.Port
	if port == 0 {
		fmt.Println("  (skipped - no TCP tunnel port)")
		fmt.Println()
		return
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		fmt.Printf("  (skipped - connect error: %v)\n", err)
		fmt.Println()
		return
	}
	defer conn.Close()

	// Send HTTP request through raw TCP tunnel
	req := "GET /1m HTTP/1.1\r\nHost: localhost\r\n\r\n"
	conn.Write([]byte(req))
	start := time.Now()
	n, _ := io.Copy(io.Discard, conn)
	elapsed := time.Since(start)

	if n > 0 {
		mbps := float64(n) / elapsed.Seconds() / 1024 / 1024
		fmt.Printf("  Download: %.1f MB/s (%d bytes in %s)\n", mbps, n, elapsed.Round(time.Millisecond))
	} else {
		fmt.Println("  (no data received)")
	}
	fmt.Println()
}

func benchTunnelCreation(env *benchEnv) {
	fmt.Println("── Tunnel Creation Speed ─────────────────────")

	count := 50
	start := time.Now()
	for i := 0; i < count; i++ {
		t, err := env.client.HTTP(env.localAddr, client.WithSubdomain(fmt.Sprintf("benchcreate%d", i)))
		if err != nil {
			fmt.Printf("  Error at tunnel %d: %v\n", i, err)
			break
		}
		_ = t
	}
	elapsed := time.Since(start)
	rate := float64(count) / elapsed.Seconds()

	fmt.Printf("  %d tunnels in %s (%.0f tunnels/sec, %.1fms each)\n",
		count, elapsed.Round(time.Millisecond), rate, float64(elapsed.Milliseconds())/float64(count))
	fmt.Println()
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
	// Simple sort
	for i := range valid {
		for j := i + 1; j < len(valid); j++ {
			if valid[j] < valid[i] {
				valid[i], valid[j] = valid[j], valid[i]
			}
		}
	}
	idx := len(valid) * pct / 100
	if idx >= len(valid) {
		idx = len(valid) - 1
	}
	return valid[idx].Round(time.Microsecond)
}

func init() {
	// Suppress server logs during benchmark
	if os.Getenv("WIRERIFT_BENCH_VERBOSE") == "" {
		// Logs go to stderr, benchmark output to stdout
	}
}
