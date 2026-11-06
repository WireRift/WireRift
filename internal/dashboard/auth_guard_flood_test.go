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

	const flood = 20000 // well above the tracked-IP cap
	for i := 0; i < flood; i++ {
		g.fail(fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
	}

	g.mu.Lock()
	n := len(g.fails)
	g.mu.Unlock()
	if n > authMaxTrackedIPs {
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

func TestAuthGuardEvictsLeastRecentlyFailedAtCapacity(t *testing.T) {
	g := &authGuard{}
	keys := make([]string, authMaxTrackedIPs)
	for i := range keys {
		keys[i] = fmt.Sprintf("tracked-%d", i)
		g.fail(keys[i])
	}

	// Refresh the oldest key, so the second inserted key becomes the LRU entry.
	g.fail(keys[0])
	g.fail("new-source")

	g.mu.Lock()
	_, refreshedSurvived := g.fails[keys[0]]
	_, oldestSurvived := g.fails[keys[1]]
	_, newestPresent := g.fails["new-source"]
	entries := len(g.fails)
	orderEntries := g.order.Len()
	g.mu.Unlock()
	if !refreshedSurvived || oldestSurvived || !newestPresent {
		t.Fatalf("LRU eviction: refreshed=%v evicted_oldest_present=%v newest=%v", refreshedSurvived, oldestSurvived, newestPresent)
	}
	if entries != authMaxTrackedIPs || orderEntries != authMaxTrackedIPs {
		t.Fatalf("capacity: map=%d order=%d want=%d", entries, orderEntries, authMaxTrackedIPs)
	}

	g.reset(keys[0])
	g.mu.Lock()
	entries = len(g.fails)
	orderEntries = g.order.Len()
	g.mu.Unlock()
	if entries != authMaxTrackedIPs-1 || orderEntries != entries {
		t.Fatalf("reset: map=%d order=%d", entries, orderEntries)
	}
}

func BenchmarkAuthGuardSaturatedNewIP(b *testing.B) {
	g := &authGuard{}
	for i := 0; i < authMaxTrackedIPs; i++ {
		g.fail(fmt.Sprintf("prefill-%d", i))
	}
	keys := make([]string, b.N)
	for i := range keys {
		keys[i] = fmt.Sprintf("candidate-%d", i)
	}
	b.ResetTimer()
	for _, key := range keys {
		g.fail(key)
	}
}
