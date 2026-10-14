package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// inspectResponseWriter wraps http.ResponseWriter to capture status and inject custom headers.
type inspectResponseWriter struct {
	http.ResponseWriter
	customHeaders map[string]string
	statusCode    int
	written       bool
}

func (w *inspectResponseWriter) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	w.statusCode = code
	// Inject custom response headers before writing
	for k, v := range w.customHeaders {
		w.ResponseWriter.Header().Set(k, v)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *inspectResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming response support.
func (w *inspectResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so WebSocket upgrades work through the wrapper.
func (w *inspectResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

// redactHeader hides credentials so the inspector (and its API) never stores
// or exposes them.
func redactHeader(key, value string) string {
	switch http.CanonicalHeaderKey(key) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Wirerift-Pin":
		return "[redacted]"
	}
	return value
}

// logRequest captures a request/response pair for the traffic inspector.
func (s *Server) logRequest(tunnel *Tunnel, r *http.Request, w *inspectResponseWriter, clientIP string, start time.Time) {
	reqHeaders := make(map[string]string)
	for k := range r.Header {
		reqHeaders[k] = redactHeader(k, strings.Join(r.Header.Values(k), ", "))
	}
	resHeaders := make(map[string]string)
	for k := range w.Header() {
		resHeaders[k] = redactHeader(k, strings.Join(w.Header().Values(k), ", "))
	}

	log := RequestLog{
		ID:         fmt.Sprintf("req_%s", generateSubdomain()),
		TunnelID:   tunnel.ID,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: w.statusCode,
		Duration:   time.Since(start),
		ReqHeaders: reqHeaders,
		ResHeaders: resHeaders,
		ReqSize:    r.ContentLength,
		ClientIP:   clientIP,
		Timestamp:  start,
	}

	s.logMu.Lock()
	s.requestLogs = append(s.requestLogs, log)
	if len(s.requestLogs) > s.maxLogs {
		kept := make([]RequestLog, s.maxLogs)
		copy(kept, s.requestLogs[len(s.requestLogs)-s.maxLogs:])
		s.requestLogs = kept
	}
	s.logMu.Unlock()
}

// GetRequestLogs returns captured request logs, optionally filtered by tunnel ID.
func (s *Server) GetRequestLogs(tunnelID string, limit int) []RequestLog {
	s.logMu.RLock()
	defer s.logMu.RUnlock()

	if limit <= 0 || limit > len(s.requestLogs) {
		limit = len(s.requestLogs)
	}

	var result []RequestLog
	// Iterate backwards (newest first)
	for i := len(s.requestLogs) - 1; i >= 0 && len(result) < limit; i-- {
		if tunnelID == "" || s.requestLogs[i].TunnelID == tunnelID {
			result = append(result, s.requestLogs[i])
		}
	}
	return result
}

// ReplayRequest replays a captured request by ID.
func (s *Server) ReplayRequest(logID string) (*RequestLog, error) {
	s.logMu.RLock()
	var original *RequestLog
	for i := range s.requestLogs {
		if s.requestLogs[i].ID == logID {
			orig := s.requestLogs[i]
			original = &orig
			break
		}
	}
	s.logMu.RUnlock()

	if original == nil {
		return nil, fmt.Errorf("request log not found: %s", logID)
	}

	// Find the tunnel
	tunnel, ok := s.getTunnelByID(original.TunnelID)
	if !ok {
		return nil, fmt.Errorf("tunnel not found: %s", original.TunnelID)
	}

	session, ok := s.getSession(tunnel.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	// Create a new HTTP request from the log
	req, _ := http.NewRequest(original.Method, original.Path, nil)
	for k, v := range original.ReqHeaders {
		req.Header.Set(k, v)
	}
	req.Host = tunnel.Subdomain + "." + s.config.Domain

	// Open stream and forward
	stream, err := session.Mux.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	openFrame, _ := StreamOpenForHTTP(tunnel.ID, stream.ID(), original.ClientIP)
	if err := session.Mux.GetFrameWriter().Write(openFrame); err != nil {
		return nil, fmt.Errorf("send stream open: %w", err)
	}

	reqData, err := SerializeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("serialize request: %w", err)
	}
	if _, err := stream.Write(reqData); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	respData, err := io.ReadAll(io.LimitReader(stream, 64*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp, err := DeserializeResponse(respData)
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}
	defer resp.Body.Close()

	resHeaders := make(map[string]string)
	for k := range resp.Header {
		resHeaders[k] = resp.Header.Get(k)
	}

	replay := &RequestLog{
		ID:         fmt.Sprintf("req_%s", generateSubdomain()),
		TunnelID:   original.TunnelID,
		Method:     original.Method,
		Path:       original.Path,
		StatusCode: resp.StatusCode,
		Duration:   0,
		ReqHeaders: original.ReqHeaders,
		ResHeaders: resHeaders,
		ClientIP:   "replay",
		Timestamp:  time.Now(),
	}

	s.logMu.Lock()
	s.requestLogs = append(s.requestLogs, *replay)
	if len(s.requestLogs) > s.maxLogs {
		s.requestLogs = append([]RequestLog(nil), s.requestLogs[len(s.requestLogs)-s.maxLogs:]...)
	}
	s.logMu.Unlock()

	return replay, nil
}

// getTunnelByID looks up a tunnel by ID across all stored tunnels.
func (s *Server) getTunnelByID(tunnelID string) (*Tunnel, bool) {
	var found *Tunnel
	s.tunnels.Range(func(key, value any) bool {
		if t, ok := value.(*Tunnel); ok && t.ID == tunnelID {
			found = t
			return false
		}
		return true
	})
	return found, found != nil
}
