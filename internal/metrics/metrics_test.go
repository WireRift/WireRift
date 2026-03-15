package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestConnectionCount(t *testing.T) {
	c := NewCollector()

	c.IncrementConnection()
	c.IncrementConnection()

	snap := c.Snapshot()
	if snap.connectionsTotal != 2 {
		t.Errorf("Expected connections_total to be 2, got %d", snap.connectionsTotal)
	}
	if snap.connectionsActive != 2 {
		t.Errorf("Expected connections_active to be 2, got %d", snap.connectionsActive)
	}

	c.DecrementConnection()

	snap = c.Snapshot()
	if snap.connectionsActive != 1 {
		t.Errorf("Expected connections_active to be 1, got %d", snap.connectionsActive)
	}
}

func TestTunnelCount(t *testing.T) {
	c := NewCollector()

	c.IncrementTunnel()
	c.IncrementTunnel()

	snap := c.Snapshot()
	if snap.tunnelsTotal != 2 {
		t.Errorf("Expected tunnels_total to be 2, got %d", snap.tunnelsTotal)
	}
	if snap.tunnelsActive != 2 {
		t.Errorf("Expected tunnels_active to be 2, got %d", snap.tunnelsActive)
	}

	c.DecrementTunnel()

	snap = c.Snapshot()
	if snap.tunnelsActive != 1 {
		t.Errorf("Expected tunnels_active to be 1, got %d", snap.tunnelsActive)
	}
}

func TestRequestCount(t *testing.T) {
	c := NewCollector()

	for i := 0; i < 100; i++ {
		c.IncrementRequest()
	}

	snap := c.Snapshot()
	if snap.requestsTotal != 100 {
		t.Errorf("Expected requests_total to be 100, got %d", snap.requestsTotal)
	}
}

func TestBytesCount(t *testing.T) {
	c := NewCollector()

	c.AddBytesIn(100)
	c.AddBytesIn(50)

	s := c.Snapshot()
	if s.bytesIn != 150 {
		t.Errorf("Expected bytes_in to be 150, got %d", s.bytesIn)
	}

	c.AddBytesOut(200)
	c.AddBytesOut(100)

	s = c.Snapshot()
	if s.bytesOut != 300 {
		t.Errorf("Expected bytes_out to be 300, got %d", s.bytesOut)
	}
}

func TestErrorCount(t *testing.T) {
	c := NewCollector()

	c.IncrementError()

	snap := c.Snapshot()
	if snap.errorsTotal != 1 {
		t.Errorf("Expected errors_total to be 1, got %d", snap.errorsTotal)
	}
}

func TestRecordLatency(t *testing.T) {
	c := NewCollector()

	// First latency
	c.RecordLatency(10 * time.Millisecond)
	snap := c.Snapshot()
	if snap.avgLatencyNs != 10_000_000 {
		t.Errorf("Expected avgLatencyNs to be 10000000, got %d", snap.avgLatencyNs)
	}
}

func TestUptime(t *testing.T) {
	c := NewCollector()
	time.Sleep(100 * time.Millisecond)

	uptime := c.Uptime()
	if uptime < 100*time.Millisecond {
		t.Errorf("Expected uptime to be at least 100ms, got %v", uptime)
	}
}

func TestPrometheusFormat(t *testing.T) {
	c := NewCollector()
	c.IncrementConnection()
	c.IncrementTunnel()
	c.IncrementRequest()

	output := c.PrometheusFormat()

	// Verify format contains expected Prometheus-compliant headers
	if !strings.Contains(output, "# HELP wirerift_connections_total") {
		t.Errorf("PrometheusFormat() output should contain expected headers")
	}
	if !strings.Contains(output, "# TYPE wirerift_connections_total counter") {
		t.Errorf("PrometheusFormat() output should contain TYPE with metric name")
	}
}

// TestRecordLatencyMultiple tests RecordLatency with multiple calls to cover the EMA branch
func TestRecordLatencyMultiple(t *testing.T) {
	c := NewCollector()

	// First call sets avgLatencyNs directly
	c.RecordLatency(10 * time.Millisecond)
	snap := c.Snapshot()
	if snap.avgLatencyNs != 10_000_000 {
		t.Errorf("After first RecordLatency: avgLatencyNs = %d, want 10000000", snap.avgLatencyNs)
	}

	// Second call should trigger the EMA branch (old != 0)
	c.RecordLatency(20 * time.Millisecond)
	snap = c.Snapshot()
	// Expected: (10_000_000 * 7 + 20_000_000 * 3) / 10 = (70_000_000 + 60_000_000) / 10 = 13_000_000
	expected := int64(13_000_000)
	if snap.avgLatencyNs != expected {
		t.Errorf("After second RecordLatency: avgLatencyNs = %d, want %d", snap.avgLatencyNs, expected)
	}

	// Third call to further exercise the EMA branch
	c.RecordLatency(5 * time.Millisecond)
	snap = c.Snapshot()
	// Expected: (13_000_000 * 7 + 5_000_000 * 3) / 10 = (91_000_000 + 15_000_000) / 10 = 10_600_000
	expected2 := int64(10_600_000)
	if snap.avgLatencyNs != expected2 {
		t.Errorf("After third RecordLatency: avgLatencyNs = %d, want %d", snap.avgLatencyNs, expected2)
	}
}

func TestHandler(t *testing.T) {
	c := NewCollector()
	handler := c.Handler()

	req, _ := http.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}
