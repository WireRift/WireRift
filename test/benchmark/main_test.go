package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSuccessfulStatusRejectsPolicyAndServerErrors(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway} {
		if successfulStatus(status) {
			t.Fatalf("status %d counted as benchmark success", status)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		if !successfulStatus(status) {
			t.Fatalf("status %d not counted as benchmark success", status)
		}
	}
}

func TestTunneledRequestUsesBoundedBenchmarkVisitorPool(t *testing.T) {
	env := &benchEnv{httpBase: "http://127.0.0.1:8080", domain: "example.test"}
	seen := make(map[string]struct{})
	for i := 0; i < 8192; i++ {
		req, err := env.tunneledRequest(http.MethodGet, "/small", nil)
		if err != nil {
			t.Fatal(err)
		}
		ip := req.Header.Get("X-Forwarded-For")
		if !strings.HasPrefix(ip, "198.18.") || req.Host != "bench.example.test" {
			t.Fatalf("request identity = host %q, IP %q", req.Host, ip)
		}
		seen[ip] = struct{}{}
	}
	if len(seen) != 4096 {
		t.Fatalf("visitor pool size = %d, want 4096", len(seen))
	}
}

func TestPercentileDoesNotMutateSamples(t *testing.T) {
	samples := []time.Duration{3 * time.Millisecond, time.Millisecond, 2 * time.Millisecond}
	if got := percentile(samples, 50); got != 2*time.Millisecond {
		t.Fatalf("p50 = %s", got)
	}
	if samples[0] != 3*time.Millisecond {
		t.Fatal("percentile mutated caller samples")
	}
}
