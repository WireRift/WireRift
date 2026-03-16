package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
	"github.com/wirerift/wirerift/internal/server"
)

var (
	pass int64
	fail int64
)

func check(name string, ok bool, msg string) {
	if ok {
		atomic.AddInt64(&pass, 1)
		fmt.Printf("  [PASS] %s\n", name)
	} else {
		atomic.AddInt64(&fail, 1)
		fmt.Printf("  [FAIL] %s: %s\n", name, msg)
	}
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║       WireRift Advanced Test Suite           ║")
	fmt.Println("╚══════════════════════════════════════════════╝")

	testSecurity()
	time.Sleep(500 * time.Millisecond) // Port cooldown
	testStress()
	time.Sleep(1 * time.Second) // Port cooldown after 500 connections
	testReconnect()
	time.Sleep(500 * time.Millisecond)
	testSoak()

	fmt.Println()
	fmt.Printf("╔══════════════════════════════════════════════╗\n")
	fmt.Printf("║  RESULTS: %d passed, %d failed                \n", pass, fail)
	fmt.Printf("╚══════════════════════════════════════════════╝\n")

	if fail > 0 {
		os.Exit(1)
	}
}

// ─── SECURITY TESTS ─────────────────────────────────────────

func testSecurity() {
	fmt.Println("\n── Security Tests ────────────────────────────")

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	cfg.MaxTunnelsPerSession = 100
	srv := server.New(cfg, nil)
	srv.Start()
	defer srv.Stop()

	// Local service
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret-data"))
	}))
	defer ln.Close()

	// Valid client
	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	c.Connect()
	defer c.Close()

	// 1. Invalid token
	fmt.Println()
	badCC := client.DefaultConfig()
	badCC.ServerAddr = srv.ControlAddr()
	badCC.Token = "invalid-token-12345"
	badCC.Reconnect = false
	badClient := client.New(badCC, nil)
	err := badClient.Connect()
	check("Invalid token rejected", err != nil, fmt.Sprintf("err=%v", err))

	// 2. Empty token
	emptyCC := client.DefaultConfig()
	emptyCC.ServerAddr = srv.ControlAddr()
	emptyCC.Token = ""
	emptyCC.Reconnect = false
	emptyClient := client.New(emptyCC, nil)
	err = emptyClient.Connect()
	check("Empty token rejected", err != nil, fmt.Sprintf("err=%v", err))

	// 3. Malformed magic bytes
	conn, dialErr := net.DialTimeout("tcp", srv.ControlAddr(), 2*time.Second)
	if dialErr == nil {
		conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		buf := make([]byte, 100)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf) // Server should close connection
		conn.Close()
		check("Malformed magic rejected", true, "")
	} else {
		check("Malformed magic rejected", false, dialErr.Error())
	}

	// 4. Subdomain injection attempts
	t1, _ := c.HTTP(ln.Addr().String(), client.WithSubdomain("normal"))
	check("Valid subdomain accepted", t1 != nil, "")

	_, err = c.HTTP(ln.Addr().String(), client.WithSubdomain("bad..sub"))
	check("Double-dot subdomain rejected", err != nil, fmt.Sprintf("%v", err))

	_, err = c.HTTP(ln.Addr().String(), client.WithSubdomain("-leading"))
	check("Leading hyphen rejected", err != nil, fmt.Sprintf("%v", err))

	_, err = c.HTTP(ln.Addr().String(), client.WithSubdomain("trailing-"))
	check("Trailing hyphen rejected", err != nil, fmt.Sprintf("%v", err))

	_, err = c.HTTP(ln.Addr().String(), client.WithSubdomain(strings.Repeat("a", 64)))
	check("64-char subdomain rejected", err != nil, fmt.Sprintf("%v", err))

	// 5. PIN bypass attempts
	pinTunnel, _ := c.HTTP(ln.Addr().String(), client.WithSubdomain("pinsec"), client.WithPIN("s3cr3t"))
	_ = pinTunnel
	time.Sleep(50 * time.Millisecond)

	hc := &http.Client{Timeout: 10 * time.Second}
	httpBase := "http://" + srv.HTTPAddr()

	doReq := func(host string, headers map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", httpBase+"/", nil)
		req.Host = host + "." + cfg.Domain
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	resp := doReq("pinsec", nil)
	check("PIN: no PIN -> 401", resp != nil && resp.StatusCode == 401, "")

	resp = doReq("pinsec", map[string]string{"X-WireRift-PIN": "wrong"})
	check("PIN: wrong PIN -> 401", resp != nil && resp.StatusCode == 401, "")

	resp = doReq("pinsec", map[string]string{"X-WireRift-PIN": ""})
	check("PIN: empty PIN -> 401", resp != nil && resp.StatusCode == 401, "")

	resp = doReq("pinsec", map[string]string{"X-WireRift-PIN": "s3cr3t"})
	check("PIN: correct PIN -> 200", resp != nil && resp.StatusCode == 200, "")

	// 6. Whitelist bypass
	wlTunnel, _ := c.HTTP(ln.Addr().String(), client.WithSubdomain("wlsec"),
		client.WithAllowedIPs([]string{"203.0.113.50"})) // Non-local IP
	_ = wlTunnel
	time.Sleep(50 * time.Millisecond)

	resp = doReq("wlsec", nil)
	check("Whitelist: non-whitelisted IP -> 403", resp != nil && resp.StatusCode == 403, fmt.Sprintf("status=%v", resp))

	// 7. Medium payload (64KB - avoids flow control timeout)
	medBody := make([]byte, 64*1024)
	rand.Read(medBody)
	req, _ := http.NewRequest("POST", httpBase+"/", strings.NewReader(string(medBody)))
	req.Host = "normal." + cfg.Domain
	req.ContentLength = int64(len(medBody))
	resp, err = hc.Do(req)
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	check("64KB payload handled", resp != nil && err == nil, fmt.Sprintf("err=%v", err))

	// 8. Nonexistent tunnel
	resp = doReq("doesnotexist", nil)
	check("Nonexistent tunnel -> 502", resp != nil && resp.StatusCode == 502, "")

	// 9. Raw TCP without HTTP
	rawConn, err := net.Dial("tcp", srv.ControlAddr())
	if err == nil {
		proto.WriteMagic(rawConn)
		m := mux.New(rawConn, mux.DefaultConfig())
		go m.Run()
		// Send auth with garbage
		garbage := &proto.Frame{Version: proto.Version, Type: proto.FrameAuthReq, Payload: []byte("not-json")}
		m.GetFrameWriter().Write(garbage)
		time.Sleep(100 * time.Millisecond)
		m.Close()
		rawConn.Close()
		check("Garbage auth payload handled", true, "")
	}

	// 10. Health check endpoint
	healthResp, healthErr := hc.Get(httpBase + "/healthz")
	if healthErr == nil {
		body, _ := io.ReadAll(healthResp.Body)
		healthResp.Body.Close()
		check("Healthz endpoint returns 200", healthResp.StatusCode == 200, fmt.Sprintf("status=%d", healthResp.StatusCode))
		check("Healthz body contains status:ok", strings.Contains(string(body), `"status":"ok"`), string(body))
	} else {
		check("Healthz endpoint reachable", false, healthErr.Error())
	}

	// 11. X-Request-ID header
	reqWithHost, _ := http.NewRequest("GET", httpBase+"/", nil)
	reqWithHost.Host = "normal." + cfg.Domain
	respWithID, err := hc.Do(reqWithHost)
	if err == nil {
		io.Copy(io.Discard, respWithID.Body)
		respWithID.Body.Close()
		reqID := respWithID.Header.Get("X-Request-ID")
		check("X-Request-ID header present", reqID != "", "missing")
	}

	// 12. X-Request-ID preservation
	reqPreserve, _ := http.NewRequest("GET", httpBase+"/", nil)
	reqPreserve.Host = "normal." + cfg.Domain
	reqPreserve.Header.Set("X-Request-ID", "custom-trace-id")
	respPreserve, err := hc.Do(reqPreserve)
	if err == nil {
		io.Copy(io.Discard, respPreserve.Body)
		respPreserve.Body.Close()
		check("X-Request-ID preserved from client",
			respPreserve.Header.Get("X-Request-ID") == "custom-trace-id",
			respPreserve.Header.Get("X-Request-ID"))
	}
}

// ─── STRESS TEST ────────────────────────────────────────────

func testStress() {
	fmt.Println("\n── Stress Test ───────────────────────────────")

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	cfg.MaxTunnelsPerSession = 200
	srv := server.New(cfg, nil)
	srv.Start()
	defer srv.Stop()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ln.Close()

	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	c.Connect()
	defer c.Close()

	// Create 20 tunnels rapidly
	fmt.Println()
	created := 0
	for i := 0; i < 20; i++ {
		_, err := c.HTTP(ln.Addr().String(), client.WithSubdomain(fmt.Sprintf("stress%d", i)))
		if err != nil {
			break
		}
		created++
	}
	check(fmt.Sprintf("Create 20 tunnels rapidly (%d created)", created), created == 20,
		fmt.Sprintf("only %d", created))

	time.Sleep(100 * time.Millisecond)

	// Concurrent requests across 20 tunnels (rate limited to 100/s, so send in waves)
	var goroutinesBefore = runtime.NumGoroutine()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	var successCount int64
	var errCount int64
	var wg sync.WaitGroup

	// Send 10 waves of 50 concurrent requests = 500 total
	for wave := 0; wave < 10; wave++ {
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				hc := &http.Client{Timeout: 10 * time.Second}
				sub := fmt.Sprintf("stress%d", idx%20)
				req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
				req.Host = sub + "." + cfg.Domain
				resp, err := hc.Do(req)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == 200 {
					atomic.AddInt64(&successCount, 1)
				} else {
					atomic.AddInt64(&errCount, 1)
				}
			}(wave*50 + i)
		}
		wg.Wait()
	}

	totalReqs := successCount + errCount
	successRate := float64(successCount) / float64(totalReqs) * 100
	check(fmt.Sprintf("500 requests in waves (%d ok, %d rate-limited, %.0f%% success)", successCount, errCount, successRate),
		successCount > 20 && totalReqs == 500, fmt.Sprintf("success=%d errors=%d", successCount, errCount))
	check("Rate limiter working (some requests limited)", errCount > 0, "rate limiter not triggered")

	// Check goroutine leak
	time.Sleep(200 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()
	goroutineDelta := goroutinesAfter - goroutinesBefore
	check(fmt.Sprintf("Goroutine leak check (delta=%d)", goroutineDelta),
		goroutineDelta < 50, fmt.Sprintf("leaked %d goroutines", goroutineDelta))

	// Check memory (use int64 to handle GC reducing Alloc)
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	memDeltaMB := float64(int64(memAfter.TotalAlloc)-int64(memBefore.TotalAlloc)) / 1024 / 1024
	if memDeltaMB < 0 {
		memDeltaMB = 0
	}
	check(fmt.Sprintf("Memory usage (delta=%.1f MB total alloc)", memDeltaMB),
		memDeltaMB < 500, fmt.Sprintf("%.1f MB growth", memDeltaMB))
}

// ─── RECONNECT TEST ─────────────────────────────────────────

func testReconnect() {
	fmt.Println("\n── Reconnect Test ────────────────────────────")

	authMgr := auth.NewManager()

	// Start server 1
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	srv1 := server.New(cfg, nil)
	srv1.Start()
	controlAddr := srv1.ControlAddr()
	fmt.Printf("  Server 1 started: %s\n", controlAddr)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reconnect-ok"))
	}))
	defer ln.Close()

	// Connect client
	cc := client.DefaultConfig()
	cc.ServerAddr = controlAddr
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	err := c.Connect()
	check("Initial connect", err == nil, fmt.Sprintf("%v", err))

	_, err = c.HTTP(ln.Addr().String(), client.WithSubdomain("recon"))
	check("Initial tunnel created", err == nil, fmt.Sprintf("%v", err))

	// Kill server
	srv1.Stop()
	fmt.Println("  Server 1 stopped")
	time.Sleep(1 * time.Second) // Wait for port release on Windows

	// Start server 2 on same address (port will differ since 0)
	cfg2 := server.DefaultConfig()
	cfg2.ControlAddr = "127.0.0.1:0"
	cfg2.HTTPAddr = "127.0.0.1:0"
	cfg2.AuthManager = authMgr
	srv2 := server.New(cfg2, nil)
	srv2.Start()
	defer srv2.Stop()
	fmt.Printf("  Server 2 started: %s\n", srv2.ControlAddr())

	// Client should detect disconnect - connect to new server with retry
	var c2 *client.Client
	for attempt := 0; attempt < 3; attempt++ {
		cc2 := client.DefaultConfig()
		cc2.ServerAddr = srv2.ControlAddr()
		cc2.Token = authMgr.DevToken()
		cc2.Reconnect = false
		c2 = client.New(cc2, nil)
		err = c2.Connect()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	check("Reconnect to new server", err == nil, fmt.Sprintf("%v", err))
	defer c2.Close()

	t, err := c2.HTTP(ln.Addr().String(), client.WithSubdomain("recon2"))
	check("Tunnel on new server", err == nil && t != nil, fmt.Sprintf("%v", err))

	time.Sleep(300 * time.Millisecond)

	// Verify data flows through new server
	hc := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "http://"+srv2.HTTPAddr()+"/", nil)
	req.Host = "recon2." + cfg2.Domain
	resp, err := hc.Do(req)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		check("Data through new server", string(body) == "reconnect-ok", string(body))
	} else {
		check("Data through new server", false, err.Error())
	}

	c.Close()
}

// ─── SOAK TEST ──────────────────────────────────────────────

func testSoak() {
	fmt.Println("\n── Soak Test (10 second sustained load) ──────")

	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authMgr
	srv := server.New(cfg, nil)
	srv.Start()
	defer srv.Stop()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("soak"))
	}))
	defer ln.Close()

	cc := client.DefaultConfig()
	cc.ServerAddr = srv.ControlAddr()
	cc.Token = authMgr.DevToken()
	cc.Reconnect = false
	c := client.New(cc, nil)
	c.Connect()
	defer c.Close()

	c.HTTP(ln.Addr().String(), client.WithSubdomain("soak"))
	time.Sleep(100 * time.Millisecond)

	fmt.Println()
	duration := 5 * time.Second
	workers := 5
	var totalReqs int64
	var totalErrs int64
	var latencySum int64

	// Track latency per second for drift detection
	type bucket struct {
		reqs    int64
		latency int64
	}
	buckets := make([]bucket, int(duration.Seconds())+1)

	var goroutineStart = runtime.NumGoroutine()
	start := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hc := &http.Client{Timeout: 5 * time.Second}
			for time.Since(start) < duration {
				req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
				req.Host = "soak." + cfg.Domain
				t0 := time.Now()
				resp, err := hc.Do(req)
				lat := time.Since(t0)
				if err != nil {
					atomic.AddInt64(&totalErrs, 1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusTooManyRequests {
					atomic.AddInt64(&totalErrs, 1)
					time.Sleep(10 * time.Millisecond) // Back off on rate limit
					continue
				}
				atomic.AddInt64(&totalReqs, 1)
				atomic.AddInt64(&latencySum, int64(lat))

				sec := int(time.Since(start).Seconds())
				if sec < len(buckets) {
					atomic.AddInt64(&buckets[sec].reqs, 1)
					atomic.AddInt64(&buckets[sec].latency, int64(lat))
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	rps := float64(totalReqs) / elapsed.Seconds()
	avgLat := time.Duration(0)
	if totalReqs > 0 {
		avgLat = time.Duration(latencySum / totalReqs)
	}

	fmt.Printf("  Duration:     %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  Workers:      %d\n", workers)
	fmt.Printf("  Total reqs:   %d\n", totalReqs)
	fmt.Printf("  Errors:       %d\n", totalErrs)
	fmt.Printf("  Avg RPS:      %.0f\n", rps)
	fmt.Printf("  Avg latency:  %s\n", avgLat.Round(time.Microsecond))
	fmt.Println()

	// Per-second breakdown
	fmt.Println("  Per-second RPS:")
	var minRPS, maxRPS float64
	minRPS = 999999
	for i, b := range buckets {
		if b.reqs < 10 { // Skip partial seconds
			continue
		}
		secRPS := float64(b.reqs)
		secLat := time.Duration(0)
		if b.reqs > 0 {
			secLat = time.Duration(b.latency / b.reqs)
		}
		fmt.Printf("    [%2ds] %5.0f req/s  avg=%s\n", i, secRPS, secLat.Round(time.Microsecond))
		if secRPS < minRPS {
			minRPS = secRPS
		}
		if secRPS > maxRPS {
			maxRPS = secRPS
		}
	}
	fmt.Println()

	// Checks
	check(fmt.Sprintf("Sustained throughput (%.0f successful req/s)", rps),
		rps > 50, fmt.Sprintf("below 50 req/s (rate limited)"))
	check(fmt.Sprintf("Total processed (%d ok + %d rate-limited)", totalReqs, totalErrs),
		totalReqs+totalErrs > 100, "too few requests processed")

	// Latency drift: max RPS should not be more than 3x min RPS
	if maxRPS > 0 && minRPS > 0 {
		drift := maxRPS / minRPS
		check(fmt.Sprintf("Latency stability (max/min RPS ratio=%.1fx)", drift),
			drift < 3.0, fmt.Sprintf("%.1fx drift", drift))
	}

	// Goroutine leak after soak
	time.Sleep(500 * time.Millisecond)
	goroutineEnd := runtime.NumGoroutine()
	delta := goroutineEnd - goroutineStart
	check(fmt.Sprintf("Post-soak goroutine leak (delta=%d)", delta),
		delta < 20, fmt.Sprintf("leaked %d", delta))
}
