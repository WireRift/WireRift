package server

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

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

// heldRecord is one reservation in the held file.
type heldRecord struct {
	Subdomain string    `json:"subdomain,omitempty"`
	Port      int       `json:"port,omitempty"` // a reserved TCP port instead of a subdomain
	AccountID string    `json:"account_id"`
	Until     time.Time `json:"until"`
}

// recordFor builds the file record of a table key ("name" or "tcp:<port>").
func recordFor(key, accountID string, until time.Time) heldRecord {
	if p, ok := strings.CutPrefix(key, tcpHoldPrefix); ok {
		if port, err := strconv.Atoi(p); err == nil {
			return heldRecord{Port: port, AccountID: accountID, Until: until}
		}
	}
	return heldRecord{Subdomain: key, AccountID: accountID, Until: until}
}

// saveHeld writes the reservations to Config.HeldFile: the names on hold and
// the names of clients that are connected now, who get OfflineGrace from this
// moment to come back to a restarted server.
func (s *Server) saveHeld() {
	if s.config.HeldFile == "" || s.config.OfflineGrace <= 0 {
		return
	}
	now := time.Now()
	until := now.Add(s.config.OfflineGrace)
	var records []heldRecord
	s.held.Range(func(k, v any) bool {
		if h := v.(heldName); now.Before(h.until) {
			records = append(records, recordFor(k.(string), h.accountID, h.until))
		}
		return true
	})
	s.sessions.Range(func(_, v any) bool {
		session := v.(*Session)
		if session.Mux != nil && session.Mux.GoAway() != nil {
			return true
		}
		session.mu.RLock()
		for _, t := range session.Tunnels {
			if t.Type == proto.TunnelTypeHTTP && t.CustomDomain == "" {
				records = append(records, heldRecord{Subdomain: t.Subdomain, AccountID: t.AccountID, Until: until})
			}
			if t.Type == proto.TunnelTypeTCP {
				records = append(records, heldRecord{Port: t.Port, AccountID: t.AccountID, Until: until})
			}
		}
		session.mu.RUnlock()
		return true
	})
	data, err := json.Marshal(records)
	if err == nil {
		tmp := s.config.HeldFile + ".tmp"
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, s.config.HeldFile)
		}
	}
	if err != nil {
		s.persistenceErrors.Add(1)
		s.logger.Warn("could not save held subdomains", "error", err)
	}
}

// loadHeld restores the reservations saved by the previous run and removes
// the file, so a crash later does not resurrect them.
func (s *Server) loadHeld() {
	if s.config.HeldFile == "" {
		return
	}
	data, err := os.ReadFile(s.config.HeldFile)
	if err != nil {
		return
	}
	_ = os.Remove(s.config.HeldFile)
	var records []heldRecord
	if json.Unmarshal(data, &records) != nil {
		return
	}
	now := time.Now()
	for _, r := range records {
		if !now.Before(r.Until) {
			continue
		}
		if r.Port > 0 {
			s.held.Store(tcpHoldKey(r.Port), heldName{accountID: r.AccountID, until: r.Until})
		} else if r.Subdomain != "" {
			s.held.Store(r.Subdomain, heldName{accountID: r.AccountID, until: r.Until})
		}
	}
}
