package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
)

var latencyBounds = [...]time.Duration{
	time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond,
	time.Second,
}

type windowStats struct {
	success   atomic.Uint64
	rejected  atomic.Uint64
	transport atomic.Uint64
	buckets   [len(latencyBounds) + 1]atomic.Uint64
}

func (s *windowStats) observe(latency time.Duration) {
	index := len(latencyBounds)
	for i, bound := range latencyBounds {
		if latency <= bound {
			index = i
			break
		}
	}
	s.buckets[index].Add(1)
}

func (s *windowStats) percentile(pct float64) time.Duration {
	total := s.success.Load()
	if total == 0 {
		return 0
	}
	want := uint64(float64(total)*pct + 0.999999)
	var seen uint64
	for i := range s.buckets {
		seen += s.buckets[i].Load()
		if seen >= want {
			if i == len(latencyBounds) {
				return 2 * time.Second
			}
			return latencyBounds[i]
		}
	}
	return 2 * time.Second
}

func main() {
	duration := flag.Duration("duration", 30*time.Second, "soak duration")
	window := flag.Duration("window", 5*time.Second, "tail-latency reporting window")
	workers := flag.Int("workers", 5, "parallel request workers")
	maxErrorRate := flag.Float64("max-error-rate", 0.001, "maximum rejected/transport fraction")
	maxP99 := flag.Duration("max-p99", 500*time.Millisecond, "maximum per-window p99")
	flag.Parse()
	if *duration < 2*time.Second || *window <= 0 || *window > *duration || *workers < 1 {
		fmt.Fprintln(os.Stderr, "soak failed: require duration>=2s, 0<window<=duration, workers>=1")
		os.Exit(2)
	}
	if err := run(*duration, *window, *workers, *maxErrorRate, *maxP99); err != nil {
		fmt.Fprintf(os.Stderr, "soak failed: %v\n", err)
		os.Exit(1)
	}
}

func run(duration, window time.Duration, workers int, maxErrorRate float64, maxP99 time.Duration) error {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "soak-ok")
	}))
	defer upstream.Close()

	authManager := auth.NewManager("soak-suite-token")
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	cfg.AuthManager = authManager
	cfg.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	srv := server.New(cfg, quiet)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	clientConfig := client.DefaultConfig()
	clientConfig.ServerAddr = srv.ControlAddr()
	clientConfig.Token = authManager.DevToken()
	clientConfig.Reconnect = false
	c := client.New(clientConfig, quiet)
	if err := c.Connect(); err != nil {
		return fmt.Errorf("connect client: %w", err)
	}
	defer c.Close()
	if _, err := c.HTTP(strings.TrimPrefix(upstream.URL, "http://"), client.WithSubdomain("scheduled-soak")); err != nil {
		return fmt.Errorf("create tunnel: %w", err)
	}

	windowCount := int((duration + window - 1) / window)
	windows := make([]windowStats, windowCount)
	var visitorID atomic.Uint64
	runtime.GC()
	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	goroutinesBefore := runtime.NumGoroutine()
	started := time.Now()
	deadline := started.Add(duration)

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			httpClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
				MaxIdleConns: 32, MaxIdleConnsPerHost: 16, IdleConnTimeout: 30 * time.Second,
			}}
			defer httpClient.CloseIdleConnections()
			for time.Now().Before(deadline) {
				index := int(time.Since(started) / window)
				if index >= len(windows) {
					index = len(windows) - 1
				}
				stats := &windows[index]
				req, err := http.NewRequest(http.MethodGet, "http://"+srv.HTTPAddr()+"/", nil)
				if err != nil {
					stats.transport.Add(1)
					continue
				}
				req.Host = "scheduled-soak." + cfg.Domain
				id := visitorID.Add(1) % 4096
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.18.%d.%d", id/256, id%256))
				requestStart := time.Now()
				resp, err := httpClient.Do(req)
				latency := time.Since(requestStart)
				if err != nil {
					stats.transport.Add(1)
					continue
				}
				body, readErr := io.ReadAll(resp.Body)
				closeErr := resp.Body.Close()
				if readErr != nil || closeErr != nil {
					stats.transport.Add(1)
					continue
				}
				if resp.StatusCode != http.StatusOK || string(body) != "soak-ok" {
					stats.rejected.Add(1)
					continue
				}
				stats.success.Add(1)
				stats.observe(latency)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(started)
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	goroutineGrowth := runtime.NumGoroutine() - goroutinesBefore
	var heapGrowth uint64
	if memoryAfter.Alloc > memoryBefore.Alloc {
		heapGrowth = memoryAfter.Alloc - memoryBefore.Alloc
	}

	var successes, rejected, transport uint64
	minP95 := time.Duration(1<<63 - 1)
	var maxP95, maxWindowP99 time.Duration
	for i := range windows {
		stats := &windows[i]
		windowSuccess := stats.success.Load()
		if windowSuccess == 0 {
			continue
		}
		p95, p99 := stats.percentile(0.95), stats.percentile(0.99)
		fmt.Printf("SOAK_WINDOW index=%d success=%d rejected=%d transport=%d p95=%s p99=%s\n",
			i, windowSuccess, stats.rejected.Load(), stats.transport.Load(), p95, p99)
		successes += windowSuccess
		rejected += stats.rejected.Load()
		transport += stats.transport.Load()
		if p95 < minP95 {
			minP95 = p95
		}
		if p95 > maxP95 {
			maxP95 = p95
		}
		if p99 > maxWindowP99 {
			maxWindowP99 = p99
		}
	}
	total := successes + rejected + transport
	if total == 0 {
		return fmt.Errorf("no requests completed")
	}
	errorRate := float64(rejected+transport) / float64(total)
	if errorRate > maxErrorRate {
		return fmt.Errorf("error rate %.6f exceeds %.6f (success=%d rejected=%d transport=%d)", errorRate, maxErrorRate, successes, rejected, transport)
	}
	if maxWindowP99 > maxP99 {
		return fmt.Errorf("window p99 %s exceeds %s", maxWindowP99, maxP99)
	}
	if minP95 > 0 && maxP95 > 3*minP95 {
		return fmt.Errorf("p95 drift %s/%s exceeds 3x", maxP95, minP95)
	}
	if goroutineGrowth > 20 {
		return fmt.Errorf("goroutine growth %d exceeds 20", goroutineGrowth)
	}
	if heapGrowth > 64<<20 {
		return fmt.Errorf("live heap growth %d exceeds 64 MiB", heapGrowth)
	}
	if float64(successes)/elapsed.Seconds() < 50 {
		return fmt.Errorf("successful throughput below 50 rps")
	}

	fmt.Printf("SOAK_OK duration=%s success=%d error_rate=%.6f rps=%.0f max_p99=%s p95_drift=%.2fx goroutine_growth=%d heap_growth_bytes=%d\n",
		elapsed.Round(time.Millisecond), successes, errorRate, float64(successes)/elapsed.Seconds(), maxWindowP99,
		float64(maxP95)/float64(minP95), goroutineGrowth, heapGrowth)
	return nil
}
