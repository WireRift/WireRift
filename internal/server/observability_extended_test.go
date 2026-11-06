package server

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scrapeMetrics(t *testing.T, s *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/metrics", nil)
	rec := httptest.NewRecorder()
	s.writePrometheusMetrics(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", rec.Code)
	}
	return rec.Body.String()
}

func TestExtendedMetricsHaveFixedCardinalityAndValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CertificateExpiry = func() time.Time { return time.Unix(2_000_000_000, 0) }
	cfg.PersistenceErrors = func() uint64 { return 3 }
	s := New(cfg, nil)
	s.observeHTTPRequest(http.StatusOK, 7*time.Millisecond)
	s.observeHTTPRequest(http.StatusNotFound, 20*time.Millisecond)
	s.observeHTTPRequest(http.StatusServiceUnavailable, 2*time.Second)
	s.persistenceErrors.Add(2)

	body := scrapeMetrics(t, s)
	for _, want := range []string{
		`wirerift_http_requests_total{class="2xx"} 1`,
		`wirerift_http_requests_total{class="4xx"} 1`,
		`wirerift_http_requests_total{class="5xx"} 1`,
		`wirerift_http_errors_total{class="4xx"} 1`,
		`wirerift_http_errors_total{class="5xx"} 1`,
		`wirerift_http_request_duration_seconds_bucket{le="0.005"} 0`,
		`wirerift_http_request_duration_seconds_bucket{le="0.01"} 1`,
		`wirerift_http_request_duration_seconds_bucket{le="0.025"} 2`,
		`wirerift_http_request_duration_seconds_bucket{le="2.5"} 3`,
		`wirerift_http_request_duration_seconds_bucket{le="+Inf"} 3`,
		`wirerift_http_request_duration_seconds_sum 2.027000`,
		`wirerift_http_request_duration_seconds_count 3`,
		`wirerift_certificate_expiry_timestamp_seconds 2000000000`,
		`wirerift_persistence_errors_total 5`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metric %q missing:\n%s", want, body)
		}
	}
	if strings.Contains(body, "path=") || strings.Contains(body, "host=") || strings.Contains(body, "method=") {
		t.Fatalf("unbounded HTTP label found:\n%s", body)
	}
}

func TestOperationalAndACMETrafficDoNotCountItself(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ACMEChallengeHandler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	s := New(cfg, nil)

	for _, path := range []string{"/metrics", "/healthz", "/.well-known/acme-challenge/token"} {
		req := httptest.NewRequest(http.MethodGet, "http://ops.example.test"+path, nil)
		rec := httptest.NewRecorder()
		s.handleHTTPRequest(rec, req)
	}
	body := scrapeMetrics(t, s)
	if !strings.Contains(body, `wirerift_http_request_duration_seconds_count 0`) {
		t.Fatalf("operational traffic counted itself:\n%s", body)
	}

	req := httptest.NewRequest(http.MethodGet, "http://missing.example.test/", nil)
	rec := httptest.NewRecorder()
	s.handleHTTPRequest(rec, req)
	body = scrapeMetrics(t, s)
	if !strings.Contains(body, `wirerift_http_requests_total{class="4xx"} 1`) {
		t.Fatalf("edge error was not counted:\n%s", body)
	}
}

type metricInterfaceWriter struct {
	header  http.Header
	flushed bool
}

func (w *metricInterfaceWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *metricInterfaceWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w *metricInterfaceWriter) WriteHeader(int)                {}
func (w *metricInterfaceWriter) Flush()                         { w.flushed = true }
func (w *metricInterfaceWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("test hijack")
}

func TestEdgeMetricWriterPreservesStreamingInterfaces(t *testing.T) {
	underlying := &metricInterfaceWriter{}
	w := newEdgeMetricWriter(underlying)
	w.Flush()
	if !underlying.flushed || w.status != http.StatusOK {
		t.Fatalf("flush: underlying=%v status=%d", underlying.flushed, w.status)
	}
	w = newEdgeMetricWriter(underlying)
	if _, _, err := w.Hijack(); err == nil || w.status != http.StatusSwitchingProtocols {
		t.Fatalf("hijack: err=%v status=%d", err, w.status)
	}
	if w.Unwrap() != underlying {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}

func TestHeldStateWriteFailureIncrementsPersistenceMetric(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HeldFile = filepath.Join(t.TempDir(), "missing", "held.json")
	s := New(cfg, nil)
	s.saveHeld()
	if got := s.persistenceErrors.Load(); got != 1 {
		t.Fatalf("persistence errors = %d, want 1", got)
	}
	if body := scrapeMetrics(t, s); !strings.Contains(body, "wirerift_persistence_errors_total 1") {
		t.Fatalf("persistence metric missing:\n%s", body)
	}
}
