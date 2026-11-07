package server

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// A TCP tunnel's public port is kept for its account just like an HTTP
// tunnel's subdomain: when the client drops, the port is reserved for
// OfflineGrace, nobody else is given it, and the client that reconnects asks
// for the same port. Reservations live in the same table as subdomains under
// the key "tcp:<port>" (a subdomain can never contain a colon).

const tcpHoldPrefix = "tcp:"

var (
	errPortTaken      = errors.New("port already taken")
	errPortOutOfRange = errors.New("port is outside the tunnel port range")
)

func tcpHoldKey(port int) string { return tcpHoldPrefix + strconv.Itoa(port) }

// holdPort reserves a dropped session's TCP port for its account.
func (s *Server) holdPort(port int, accountID string) {
	if s.config.OfflineGrace <= 0 {
		return
	}
	s.held.Store(tcpHoldKey(port), heldName{accountID: accountID, until: time.Now().Add(s.config.OfflineGrace)})
}

// heldPortBy reports whether the port is reserved and for which account.
func (s *Server) heldPortBy(port int) (accountID string, held bool) {
	return s.heldBy(tcpHoldKey(port))
}

// listenTCPForRequest opens the listener for a TCP tunnel request: the port the
// client asks for (RemotePort, set by a client re-creating its tunnel after a
// drop, or by one that wants a fixed port), or any free port of the range.
func (s *Server) listenTCPForRequest(session *Session, req *proto.TunnelRequest) (net.Listener, int, error) {
	if req.RemotePort == 0 {
		return s.listenTunnelPort()
	}
	port := req.RemotePort
	if port < s.tcpPortStart || port > s.tcpPortEnd {
		return nil, 0, errPortOutOfRange
	}
	if owner, held := s.heldPortBy(port); held && owner != session.AccountID {
		return nil, 0, errPortTaken
	}
	// A client that reconnects after a network drop finds its previous session
	// (and the port) still registered until the server notices the silence.
	if v, ok := s.tunnels.Load(tcpHoldKey(port)); ok {
		old, isTunnel := v.(*Tunnel)
		if !isTunnel || !req.Reconnect || old.AccountID != session.AccountID || old.SessionID == session.ID {
			return nil, 0, errPortTaken
		}
		s.evictTCPTunnel(old)
	}
	if _, loaded := s.tcpPorts.LoadOrStore(port, true); loaded {
		return nil, 0, errPortTaken
	}
	listener, err := net.Listen("tcp", s.tcpListenAddr(port))
	if err != nil {
		s.releasePort(port)
		if isAddrInUse(err) {
			return nil, 0, errPortTaken
		}
		return nil, 0, err
	}
	return listener, port, nil
}

// evictTCPTunnel tears down a tunnel of a session that is about to be replaced
// by the same account's new session. It is detached from its session, so
// ending that session later neither tears it down again nor holds the port.
func (s *Server) evictTCPTunnel(old *Tunnel) {
	if sv, ok := s.sessions.Load(old.SessionID); ok {
		prev := sv.(*Session)
		prev.mu.Lock()
		delete(prev.Tunnels, old.ID)
		prev.mu.Unlock()
	}
	s.teardownTunnel(old)
}

// wsaeAddrUse is Winsock's WSAEADDRINUSE (it is not syscall.EADDRINUSE there).
const wsaeAddrUse = syscall.Errno(10048)

// isAddrInUse reports an "address already in use" bind failure on any platform.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, wsaeAddrUse)
}
