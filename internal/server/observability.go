package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

const (
	prometheusContentType   = "text/plain; version=0.0.4; charset=utf-8"
	httpDurationBucketSlots = 12 // eleven finite bounds plus +Inf
)

var httpDurationBounds = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// edgeMetricWriter records the final status without breaking interfaces used
// by streaming and WebSocket responses.
type edgeMetricWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func newEdgeMetricWriter(w http.ResponseWriter) *edgeMetricWriter {
	return &edgeMetricWriter{ResponseWriter: w, status: http.StatusOK}
}

func (w *edgeMetricWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *edgeMetricWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *edgeMetricWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *edgeMetricWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = http.StatusSwitchingProtocols
	}
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *edgeMetricWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) observeHTTPRequest(status int, elapsed time.Duration) {
	class := status / 100
	if class < 1 || class > 5 {
		class = 5
	}
	s.httpStatus[class-1].Add(1)
	s.httpDurationNanos.Add(elapsed.Nanoseconds())
	seconds := elapsed.Seconds()
	bucket := len(httpDurationBounds)
	for i, bound := range httpDurationBounds {
		if seconds <= bound {
			bucket = i
			break
		}
	}
	s.httpDurationBuckets[bucket].Add(1)
}

// handleOperationalEndpoint serves unauthenticated endpoints intended for
// orchestrators and monitoring systems. The caller is responsible for ensuring
// the request host does not belong to a tunnel.
func (s *Server) handleOperationalEndpoint(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/healthz", "/health/ready", "/metrics":
	default:
		return false
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	switch r.URL.Path {
	case "/healthz":
		writeOperationalJSON(w, r, http.StatusOK, `{"status":"ok"}`)
	case "/health/ready":
		if !s.ready.Load() {
			writeOperationalJSON(w, r, http.StatusServiceUnavailable, `{"status":"not_ready"}`)
			return true
		}
		writeOperationalJSON(w, r, http.StatusOK, `{"status":"ready"}`)
	case "/metrics":
		if !s.metricsAllowed(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="wirerift-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return true
		}
		s.writePrometheusMetrics(w, r)
	}
	return true
}

// metricsAllowed gates /metrics: topology and traffic counts are not for the
// public. A direct loopback peer (a local Prometheus or curl) is trusted; a
// loopback peer that forwards someone else's request (a same-host reverse
// proxy sets a forwarding header) is not. Everyone else needs a valid token.
func (s *Server) metricsAllowed(r *http.Request) bool {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() &&
			r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("Forwarded") == "" &&
			r.Header.Get("X-Real-Ip") == "" {
			return true
		}
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	_, _, err := s.authManager.ValidateToken(strings.TrimSpace(h[len(prefix):]))
	return err == nil
}

func writeOperationalJSON(w http.ResponseWriter, r *http.Request, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

func (s *Server) writePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	ready := s.ready.Load()
	readyValue := 0
	uptime := 0.0
	if ready {
		readyValue = 1
		if started := s.startTime; !started.IsZero() {
			uptime = time.Since(started).Seconds()
		}
	}

	var sessions, httpTunnels, tcpTunnels int
	s.sessions.Range(func(_, _ any) bool {
		sessions++
		return true
	})
	s.tunnels.Range(func(key, value any) bool {
		if isAliasKey(key) {
			return true
		}
		tunnel, ok := value.(*Tunnel)
		if !ok {
			return true
		}
		switch tunnel.Type {
		case proto.TunnelTypeHTTP:
			httpTunnels++
		case proto.TunnelTypeTCP:
			tcpTunnels++
		}
		return true
	})

	var body strings.Builder
	fmt.Fprintf(&body, "# HELP wirerift_server_ready Whether all configured listeners and maintenance loops are running.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_server_ready gauge\n")
	fmt.Fprintf(&body, "wirerift_server_ready %d\n", readyValue)
	fmt.Fprintf(&body, "# HELP wirerift_server_uptime_seconds Seconds since the server became ready.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_server_uptime_seconds gauge\n")
	fmt.Fprintf(&body, "wirerift_server_uptime_seconds %.3f\n", uptime)
	fmt.Fprintf(&body, "# HELP wirerift_sessions_active Currently connected client sessions.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_sessions_active gauge\n")
	fmt.Fprintf(&body, "wirerift_sessions_active %d\n", sessions)
	fmt.Fprintf(&body, "# HELP wirerift_tunnels_active Currently active tunnels by type.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_tunnels_active gauge\n")
	fmt.Fprintf(&body, "wirerift_tunnels_active{type=\"http\"} %d\n", httpTunnels)
	fmt.Fprintf(&body, "wirerift_tunnels_active{type=\"tcp\"} %d\n", tcpTunnels)
	fmt.Fprintf(&body, "# HELP wirerift_edge_bytes_total Bytes transferred through edge tunnels by direction.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_edge_bytes_total counter\n")
	fmt.Fprintf(&body, "wirerift_edge_bytes_total{direction=\"in\"} %d\n", s.bytesIn.Load())
	fmt.Fprintf(&body, "wirerift_edge_bytes_total{direction=\"out\"} %d\n", s.bytesOut.Load())

	fmt.Fprintf(&body, "# HELP wirerift_http_requests_total Tunnel HTTP requests by bounded status class.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_http_requests_total counter\n")
	var requestCount uint64
	for i := range s.httpStatus {
		count := s.httpStatus[i].Load()
		requestCount += count
		fmt.Fprintf(&body, "wirerift_http_requests_total{class=\"%dxx\"} %d\n", i+1, count)
	}
	fmt.Fprintf(&body, "# HELP wirerift_http_errors_total Tunnel HTTP error responses by bounded status class.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_http_errors_total counter\n")
	fmt.Fprintf(&body, "wirerift_http_errors_total{class=\"4xx\"} %d\n", s.httpStatus[3].Load())
	fmt.Fprintf(&body, "wirerift_http_errors_total{class=\"5xx\"} %d\n", s.httpStatus[4].Load())

	fmt.Fprintf(&body, "# HELP wirerift_http_request_duration_seconds Tunnel HTTP request duration with fixed global buckets.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_http_request_duration_seconds histogram\n")
	var cumulative uint64
	for i, bound := range httpDurationBounds {
		cumulative += s.httpDurationBuckets[i].Load()
		fmt.Fprintf(&body, "wirerift_http_request_duration_seconds_bucket{le=\"%g\"} %d\n", bound, cumulative)
	}
	cumulative += s.httpDurationBuckets[len(httpDurationBounds)].Load()
	fmt.Fprintf(&body, "wirerift_http_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	fmt.Fprintf(&body, "wirerift_http_request_duration_seconds_sum %.6f\n", float64(s.httpDurationNanos.Load())/float64(time.Second))
	fmt.Fprintf(&body, "wirerift_http_request_duration_seconds_count %d\n", requestCount)

	var certificateExpiry int64
	if s.config.CertificateExpiry != nil {
		if expiry := s.config.CertificateExpiry(); !expiry.IsZero() {
			certificateExpiry = expiry.Unix()
		}
	}
	fmt.Fprintf(&body, "# HELP wirerift_certificate_expiry_timestamp_seconds Earliest expiry among certificates already loaded in memory, or zero when unavailable.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_certificate_expiry_timestamp_seconds gauge\n")
	fmt.Fprintf(&body, "wirerift_certificate_expiry_timestamp_seconds %d\n", certificateExpiry)

	persistenceErrors := s.persistenceErrors.Load()
	if s.config.PersistenceErrors != nil {
		persistenceErrors += s.config.PersistenceErrors()
	}
	fmt.Fprintf(&body, "# HELP wirerift_persistence_errors_total Persistent-state write failures observed by the server and TLS manager.\n")
	fmt.Fprintf(&body, "# TYPE wirerift_persistence_errors_total counter\n")
	fmt.Fprintf(&body, "wirerift_persistence_errors_total %d\n", persistenceErrors)

	w.Header().Set("Content-Type", prometheusContentType)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body.String()))
	}
}
