package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// maxRequestBodySize bounds the request body buffered for tunneling.
const maxRequestBodySize = 32 * 1024 * 1024

// maxForwardedForHops bounds work on attacker-controlled forwarding headers.
const maxForwardedForHops = 32

// ErrRequestTooLarge is returned when a request body exceeds maxRequestBodySize.
var ErrRequestTooLarge = errors.New("request body too large")

func parseTrustedProxyCIDRs(specs []string) ([]netip.Prefix, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(specs))
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			return nil, errors.New("empty CIDR")
		}
		prefix, err := netip.ParsePrefix(spec)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", spec, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func parseRemoteIP(remoteAddr string) (string, netip.Addr, bool) {
	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return host, netip.Addr{}, false
	}
	addr = addr.WithZone("").Unmap()
	return addr.String(), addr, true
}

func containsIP(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP resolves the visitor consistently for access controls, inspection,
// stream metadata, and backend forwarding. Forwarding headers are considered
// only when the immediate socket peer is explicitly trusted.
func (s *Server) clientIP(r *http.Request) string {
	peerText, peer, validPeer := parseRemoteIP(r.RemoteAddr)
	if !validPeer || !containsIP(s.trustedProxyNets, peer) {
		return peerText
	}

	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peerText
	}
	chain := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if len(chain) >= maxForwardedForHops {
				return peerText
			}
			addr, err := netip.ParseAddr(strings.TrimSpace(token))
			if err != nil || addr.Zone() != "" {
				return peerText
			}
			chain = append(chain, addr.Unmap())
		}
	}
	if len(chain) == 0 {
		return peerText
	}

	// Walk from the trusted socket peer towards the visitor. The first
	// untrusted hop is the client boundary; any values to its left are claims
	// made by that untrusted hop and must be ignored.
	client := peerText
	for i := len(chain) - 1; i >= 0; i-- {
		client = chain[i].String()
		if !containsIP(s.trustedProxyNets, chain[i]) {
			return client
		}
	}
	return client
}

// skipForwardHeader reports headers that must not be copied verbatim from the
// visitor: the proxy re-emits trusted values (forwarding headers), the framing
// is recomputed from the buffered body, and the PIN is a credential for this
// server that must not leak to the local app.
func skipForwardHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
		"Content-Length", "Transfer-Encoding", "X-Wirerift-Pin":
		return true
	}
	return false
}

// SerializeRequest serializes an HTTP request for tunneling.
func SerializeRequest(r *http.Request) ([]byte, error) {
	head, body, err := serializeRequestParts(r)
	if err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

func (s *Server) serializeRequest(r *http.Request) ([]byte, error) {
	head, body, err := s.serializeRequestParts(r)
	if err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

// serializeRequestParts returns the request head and its buffered body
// separately, so a caller can send them one after the other without a third
// copy of a large body.
func serializeRequestParts(r *http.Request) (head, body []byte, err error) {
	clientIP, _, _ := parseRemoteIP(r.RemoteAddr)
	return serializeRequestPartsFor(r, clientIP)
}

func (s *Server) serializeRequestParts(r *http.Request) (head, body []byte, err error) {
	return serializeRequestPartsFor(r, s.clientIP(r))
}

func serializeRequestPartsFor(r *http.Request, clientIP string) (head, body []byte, err error) {
	// Buffer the body first so the framing headers match what is sent.
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
		if err != nil {
			return nil, nil, err
		}
		if len(body) > maxRequestBodySize {
			return nil, nil, ErrRequestTooLarge
		}
	}

	var buf bytes.Buffer

	// Write request line
	buf.WriteString(r.Method)
	buf.WriteByte(' ')
	buf.WriteString(r.URL.String())
	buf.WriteByte(' ')
	buf.WriteString(r.Proto)
	buf.WriteString("\r\n")

	// Write headers
	for key, values := range r.Header {
		if skipForwardHeader(key) {
			continue
		}
		for _, value := range values {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}

	// RFC 9112 Section 3.2: an HTTP/1.1 request on the wire must carry a
	// Host header. net/http removes Host from r.Header, so the loop above
	// never emits it; without this line the tunneled request reaches the
	// local service with an empty Host (or none), which strict servers —
	// including Go's own net/http server — reject with 400, breaking the
	// WebSocket relay and any Host-based routing on the local app.
	if r.Host != "" {
		buf.WriteString("Host: ")
		buf.WriteString(r.Host)
		buf.WriteString("\r\n")
	}

	// Add forwarding headers (exactly one of each, never client-supplied
	// duplicates that a backend could read first).
	buf.WriteString("X-Forwarded-For: ")
	// The edge is the trust boundary. A direct visitor can supply any incoming
	// X-Forwarded-For value, so forwarding or appending it lets that visitor
	// spoof the client IP seen by common backend frameworks.
	buf.WriteString(clientIP)
	buf.WriteString("\r\n")
	buf.WriteString("X-Forwarded-Proto: ")
	if r.TLS != nil {
		buf.WriteString("https")
	} else {
		buf.WriteString("http")
	}
	buf.WriteString("\r\n")
	buf.WriteString("X-Forwarded-Host: ")
	buf.WriteString(r.Host)
	buf.WriteString("\r\n")

	// Body framing: chunked/unknown-length bodies were decoded by net/http,
	// so always declare the real length.
	if len(body) > 0 || r.ContentLength != 0 {
		buf.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}

	// End headers
	buf.WriteString("\r\n")

	return buf.Bytes(), body, nil
}

// DeserializeResponse deserializes an HTTP response from tunneling.
func DeserializeResponse(data []byte) (*http.Response, error) {
	return DeserializeResponseFor(data, nil)
}

// DeserializeResponseFor deserializes a response to req. Passing the request
// matters for HEAD: its response carries Content-Length but no body, which
// would otherwise surface as an unexpected EOF while copying the body.
func DeserializeResponseFor(data []byte, req *http.Request) (*http.Response, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// WriteResponse writes an HTTP response to the client.
func WriteResponse(w http.ResponseWriter, resp *http.Response) error {
	return writeResponseIdle(w, resp, 0)
}

// writeResponseIdle is WriteResponse with an idle write deadline (0 = none).
func writeResponseIdle(w http.ResponseWriter, resp *http.Response, idle time.Duration) error {
	if idle > 0 {
		w = newDeadlineWriter(w, idle)
	}

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy body. When the length is not declared (chunked, close-delimited,
	// SSE) flush after every chunk so data reaches the visitor immediately.
	if resp.Body != nil {
		defer resp.Body.Close()
		flusher, _ := w.(http.Flusher)
		if flusher == nil || (resp.ContentLength >= 0 && !isEventStream(resp)) {
			_, err := io.Copy(w, resp.Body)
			return err
		}
		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return werr
				}
				flusher.Flush()
			}
			if rerr == io.EOF {
				return nil
			}
			if rerr != nil {
				return rerr
			}
		}
	}

	return nil
}

func isEventStream(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
}

// IsWebSocketRequest checks if a request is a WebSocket upgrade per RFC 6455.
func IsWebSocketRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	// Connection header must contain "upgrade" (RFC 6455 Section 4.2.1)
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// deadlineWriter restarts the connection's write deadline before every write
// and flush, turning the server's absolute WriteTimeout into an idle timeout:
// a response may take as long as it likes as long as the visitor keeps reading.
type deadlineWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func newDeadlineWriter(w http.ResponseWriter, idle time.Duration) *deadlineWriter {
	return &deadlineWriter{ResponseWriter: w, rc: http.NewResponseController(w), idle: idle}
}

func (d *deadlineWriter) extend() {
	if d.idle > 0 {
		_ = d.rc.SetWriteDeadline(time.Now().Add(d.idle)) // ErrNotSupported (recorders, h2) is fine
	}
}

func (d *deadlineWriter) WriteHeader(code int) { d.extend(); d.ResponseWriter.WriteHeader(code) }

func (d *deadlineWriter) Write(p []byte) (int, error) { d.extend(); return d.ResponseWriter.Write(p) }

func (d *deadlineWriter) Flush() { d.extend(); _ = d.rc.Flush() }

// Unwrap exposes the underlying writer to http.ResponseController.
func (d *deadlineWriter) Unwrap() http.ResponseWriter { return d.ResponseWriter }

// idleBody restarts the connection's read deadline before every read of a
// request body, so uploads of any size work while a stalled uploader is dropped.
type idleBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	idle time.Duration
}

func (b *idleBody) Read(p []byte) (int, error) {
	if b.idle > 0 {
		_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	}
	return b.ReadCloser.Read(p)
}
