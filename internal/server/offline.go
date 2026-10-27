package server

import "time"

// heldName remembers who owned a subdomain when its session dropped.
type heldName struct {
	accountID string
	until     time.Time
}

// holdSubdomain keeps a dropped session's subdomain for its account for
// OfflineGrace, so the client that reconnects gets the same URL back and
// nobody else can take the name in the meantime.
func (s *Server) holdSubdomain(subdomain, accountID string) {
	if s.config.OfflineGrace <= 0 {
		return
	}
	s.held.Store(subdomain, heldName{accountID: accountID, until: time.Now().Add(s.config.OfflineGrace)})
}

// heldBy reports whether the subdomain is on hold and for which account.
// Expired holds are dropped on the way.
func (s *Server) heldBy(subdomain string) (accountID string, held bool) {
	v, ok := s.held.Load(subdomain)
	if !ok {
		return "", false
	}
	h := v.(heldName)
	if time.Now().After(h.until) {
		s.held.CompareAndDelete(subdomain, h)
		return "", false
	}
	return h.accountID, true
}

// sweepHeld drops expired holds that nobody asked about.
func (s *Server) sweepHeld() {
	now := time.Now()
	s.held.Range(func(k, v any) bool {
		if now.After(v.(heldName).until) {
			s.held.CompareAndDelete(k, v)
		}
		return true
	})
}
