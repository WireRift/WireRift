package client

import (
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Exchange describes one visitor exchange the client relayed to a local
// service, for local inspection (the client's web UI). It is delivered to
// Config.OnExchange when the exchange ends.
type Exchange struct {
	ID        uint64
	Time      time.Time // when the visitor's request arrived
	Duration  time.Duration
	TunnelID  string
	TunnelURL string
	LocalAddr string
	Kind      string // "http", "websocket" or "tcp"
	Method    string
	Path      string // request URI (path and query)
	Host      string // the Host header the visitor used
	Remote    string // the visitor's address when the server passed it on
	Status    int    // HTTP status; 502 when the local service did not answer
	BytesIn   int64  // visitor -> local service (body bytes for HTTP)
	BytesOut  int64  // local service -> visitor
	Error     string // why the local service could not be reached, if so

	ReqHeader  http.Header
	RespHeader http.Header
	ReqBody    []byte // at most Config.CaptureBody bytes
	RespBody   []byte
	// BodyTruncated is set when a body was longer than the capture limit.
	ReqTruncated  bool
	RespTruncated bool
}

// TunnelInfo is a snapshot of one open tunnel.
type TunnelInfo struct {
	ID        string
	Type      string
	PublicURL string
	LocalAddr string
	Subdomain string
	Port      int
	ExpiresAt time.Time
}

// Tunnels returns the tunnels that are open now (after a reconnect these are
// the re-created ones, with their new IDs), ordered by public address.
func (c *Client) Tunnels() []TunnelInfo {
	var out []TunnelInfo
	c.tunnels.Range(func(_, v any) bool {
		t := v.(*Tunnel)
		if t.isClosed() {
			return true
		}
		t.mu.Lock()
		out = append(out, TunnelInfo{
			ID: t.ID, Type: string(t.Type), PublicURL: t.PublicURL, LocalAddr: t.LocalAddr,
			Subdomain: t.Subdomain, Port: t.Port, ExpiresAt: t.ExpiresAt,
		})
		t.mu.Unlock()
		return true
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].PublicURL+strconv.Itoa(out[i].Port) < out[j].PublicURL+strconv.Itoa(out[j].Port)
	})
	return out
}

// capture keeps the first limit bytes that pass through it and counts them all.
// The transport may still read a request body after the response has started,
// so it is guarded.
type capture struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	n         int64
	truncated bool
}

func (c *capture) add(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += int64(len(p))
	room := c.limit - len(c.buf)
	switch {
	case room <= 0:
		c.truncated = c.truncated || len(p) > 0
	case len(p) > room:
		c.buf = append(c.buf, p[:room]...)
		c.truncated = true
	default:
		c.buf = append(c.buf, p...)
	}
}

func (c *capture) result() (body []byte, n int64, truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...), c.n, c.truncated
}

type captureBody struct {
	io.ReadCloser
	cap *capture
}

func (b *captureBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.cap.add(p[:n])
	}
	return n, err
}

// recorder builds one Exchange while an HTTP request is relayed.
type recorder struct {
	c      *Client
	ex     Exchange
	reqCap *capture
	rspCap *capture
}

func (c *Client) beginExchange(t *Tunnel, req *http.Request) *recorder {
	r := &recorder{c: c, reqCap: &capture{limit: c.config.CaptureBody}, rspCap: &capture{limit: c.config.CaptureBody}}
	t.mu.Lock()
	r.ex = Exchange{
		ID: c.exchangeSeq.Add(1), Time: time.Now(), TunnelID: t.ID, TunnelURL: t.PublicURL, LocalAddr: t.LocalAddr,
		Kind: "http", Method: req.Method, Path: req.URL.RequestURI(), Host: req.Host,
		Remote: visitorAddr(req.Header), ReqHeader: req.Header.Clone(),
	}
	t.mu.Unlock()
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = &captureBody{ReadCloser: req.Body, cap: r.reqCap}
	}
	return r
}

// visitorAddr is the visitor address the server forwarded, if any.
func visitorAddr(h http.Header) string {
	if v := h.Get("X-Forwarded-For"); v != "" {
		first, _, _ := strings.Cut(v, ",")
		return strings.TrimSpace(first)
	}
	return h.Get("X-Real-Ip")
}

// wrapResponse counts and captures the body that resp.Write is about to send.
func (r *recorder) wrapResponse(resp *http.Response) {
	r.ex.Status = resp.StatusCode
	r.ex.RespHeader = resp.Header.Clone()
	if resp.Body != nil && resp.Body != http.NoBody {
		resp.Body = &captureBody{ReadCloser: resp.Body, cap: r.rspCap}
	}
}

// finish delivers the exchange; err is why the local service did not answer.
func (r *recorder) finish(err error) {
	if err != nil {
		r.ex.Status = http.StatusBadGateway
		r.ex.Error = err.Error()
	}
	r.ex.Duration = time.Since(r.ex.Time)
	r.ex.ReqBody, r.ex.BytesIn, r.ex.ReqTruncated = r.reqCap.result()
	r.ex.RespBody, r.ex.BytesOut, r.ex.RespTruncated = r.rspCap.result()
	r.c.config.OnExchange(r.ex)
}

// emitStream delivers a WebSocket or TCP relay that has ended.
func (c *Client) emitStream(t *Tunnel, kind string, start time.Time, in, out int64, method, path, host string, hdr http.Header, errMsg string) {
	if c.config.OnExchange == nil {
		return
	}
	t.mu.Lock()
	ex := Exchange{
		ID: c.exchangeSeq.Add(1), Time: start, Duration: time.Since(start), TunnelID: t.ID, TunnelURL: t.PublicURL,
		LocalAddr: t.LocalAddr, Kind: kind, Method: method, Path: path, Host: host,
		BytesIn: in, BytesOut: out, ReqHeader: hdr, Error: errMsg,
	}
	t.mu.Unlock()
	if hdr != nil {
		ex.Remote = visitorAddr(hdr)
	}
	c.config.OnExchange(ex)
}
