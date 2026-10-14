package dashboard

// Regression test for the authGuard memory bound. The "bound memory" sweep
// in fail() only evicts entries that are already expired, so a flood of
// failed logins from many distinct fresh IPs grew the map without bound —
// one entry per unique source address, for as long as the flood lasts.
// The dashboard is Internet-bindable and shares the wirerift-server
// process, so that growth is memory exhaustion for every tunnel. A guard
// under a live flood must hold the map at its documented cap.

import (
	"fmt"
	"testing"
)

func TestAuthGuardMemoryBoundedUnderDistinctIPFlood(t *testing.T) {
	g := &authGuard{}

	const flood = 20000 // well above the 10000-entry cap
	for i := 0; i < flood; i++ {
		g.fail(fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
	}

	g.mu.Lock()
	n := len(g.fails)
	g.mu.Unlock()
	if n > 10000 {
		t.Fatalf("FAIL: authGuard map grew to %d entries after %d distinct-IP failures — "+
			"the sweep evicts only expired entries, so a fresh-IP flood grows the "+
			"map without bound (documented as 'bound memory')", n, flood)
	}

	// Control: the throttle itself still works after the flood.
	for i := 0; i < authMaxFailures; i++ {
		g.fail("203.0.113.9")
	}
	if !g.locked("203.0.113.9") {
		t.Error("control: IP with authMaxFailures failures should be locked")
	}
	if g.locked("10.0.0.2") {
		t.Error("control: a single failed attempt must not lock an IP")
	}
}
