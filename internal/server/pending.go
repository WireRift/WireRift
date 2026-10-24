package server

import (
	"net"
	"sync"
)

// Limits on control connections that have not authenticated yet. Each one costs
// a goroutine, a file descriptor and (over TLS) a handshake, so an anonymous
// peer must not be able to open them without bound.
const (
	maxPendingControlConns      = 1024
	maxPendingControlConnsPerIP = 32
)

// pendingConns counts unauthenticated control connections, overall and per
// remote IP. The zero value is ready to use.
type pendingConns struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

// acquire reserves a slot for a connection from addr. The returned release must
// be called once the connection has authenticated or gone away; it is safe to
// call more than once.
func (p *pendingConns) acquire(addr net.Addr) (release func(), ok bool) {
	ip := ""
	if addr != nil {
		ip = addr.String()
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.perIP == nil {
		p.perIP = make(map[string]int)
	}
	if p.total >= maxPendingControlConns || p.perIP[ip] >= maxPendingControlConnsPerIP {
		return nil, false
	}
	p.total++
	p.perIP[ip]++

	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.total--
			if p.perIP[ip]--; p.perIP[ip] <= 0 {
				delete(p.perIP, ip)
			}
		})
	}, true
}
