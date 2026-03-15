package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterAllow(t *testing.T) {
	// 10 tokens per second, burst of 5
	limiter := New(10, 5)

	// Should allow burst
	for i := 0; i < 5; i++ {
		if !limiter.Allow() {
			t.Errorf("Allow() = false, want true at iteration %d", i)
		}
	 }

	 // Should deny 6th request
    if limiter.Allow() {
        t.Error("Allow() = true after burst, want false")
    }
}

func TestLimiterAllowN(t *testing.T) {
    // 10 tokens per second, burst of 5
    limiter := New(10, 5)

    // Should allow taking 1 token at a time (5 times)
    for i := 0; i < 5; i++ {
        if !limiter.AllowN(1) {
            t.Errorf("AllowN(1) = false, want true at iteration %d", i)
        }
    }

    // All tokens consumed, should deny
    if limiter.AllowN(1) {
        t.Error("AllowN(1) after burst, want false")
    }
}

func TestLimiterRefill(t *testing.T) {
    // 100 tokens per second, burst of 5
    limiter := New(100, 5)

    // Consume all tokens
    for i := 0; i < 5; i++ {
        limiter.Allow()
    }

    // Wait for refill
    time.Sleep(60 * time.Millisecond)

    // Should have tokens now
    if !limiter.Allow() {
        t.Error("Allow() = false after refill time, want true")
    }
}

func TestLimiterTokens(t *testing.T) {
    limiter := New(10, 10)

    // Initial tokens should be burst size
    if limiter.Tokens() != 10 {
        t.Errorf("Initial tokens = %v, want 10", limiter.Tokens())
    }

    // Consume some tokens
    limiter.AllowN(3)

    // Should have 7 tokens (approximately)
    tokens := limiter.Tokens()
    if tokens < 6.9 || tokens > 7.1 {
        t.Errorf("Tokens after consuming 3 = %v, want ~7", tokens)
    }
}

func TestLimiterRate(t *testing.T) {
    limiter := New(10, 5)

    if limiter.Rate() != 10 {
        t.Errorf("Rate() = %v, want 10", limiter.Rate())
    }

    limiter.SetRate(20)

    if limiter.Rate() != 20 {
        t.Errorf("Rate() after SetRate = %v, want 20", limiter.Rate())
    }
}

func TestLimiterBurst(t *testing.T) {
    limiter := New(10, 5)

    if limiter.Burst() != 5 {
        t.Errorf("Burst() = %v, want 5", limiter.Burst())
    }
}

func TestManager(t *testing.T) {
    mgr := NewManager(10, 5)

    // Get limiter for key1
    limiter1 := mgr.Get("key1")
    if limiter1 == nil {
        t.Fatal("Get returned nil")
    }

    // Should be same limiter on second call
    limiter1Again := mgr.Get("key1")
    if limiter1 != limiter1Again {
        t.Error("Get returned different limiter for same key")
    }

    // Different key should have different limiter
    limiter2 := mgr.Get("key2")
    if limiter1 == limiter2 {
        t.Error("Get returned same limiter for different keys")
    }
}

func TestManagerAllow(t *testing.T) {
    mgr := NewManager(10, 3)

    // Should allow burst
    for i := 0; i < 3; i++ {
        if !mgr.Allow("key1") {
            t.Errorf("Allow() = false, want true at iteration %d", i)
        }
    }

    // Should deny
    if mgr.Allow("key1") {
        t.Error("Allow() = true after burst, want false")
    }
}

func TestManagerRemove(t *testing.T) {
    mgr := NewManager(10, 3)

    // Exhaust limiter
    for i := 0; i < 3; i++ {
        mgr.Allow("key1")
    }

    // Remove it
    mgr.Remove("key1")

    // Get should create new limiter
    if !mgr.Allow("key1") {
        t.Error("Allow() = false for new limiter after Remove, want true")
    }
}

func TestLimiterWait(t *testing.T) {
    // High rate to avoid long waits
    limiter := New(1000, 1)

    // Consume the only token
    limiter.Allow()

    // Wait should block until token is available
    done := make(chan bool)
    go func() {
        limiter.Wait()
        done <- true
    }()

    select {
    case <-done:
        // Success - Wait returned after token refill
    case <-time.After(100 * time.Millisecond):
        t.Error("Wait() did not return in time")
    }
}

func TestLimiterWaitN(t *testing.T) {
    // High rate to avoid long waits
    limiter := New(1000, 2)

    // Consume all tokens
    limiter.AllowN(2)

    // WaitN should block until tokens are available
    done := make(chan bool)
    go func() {
        limiter.WaitN(1)
        done <- true
    }()

    select {
    case <-done:
        // Success
    case <-time.After(100 * time.Millisecond):
        t.Error("WaitN() did not return in time")
    }
}

func TestLimiterReserve(t *testing.T) {
    // Very low rate (1 token per second), burst of 1
    limiter := New(1, 1)

    // First reserve should be instant (1 token available)
    wait := limiter.Reserve()
    if wait != 0 {
        t.Errorf("First Reserve() wait = %v, want 0", wait)
    }

    // Token consumed immediately, need to wait ~1 second for next
    wait = limiter.Reserve()
    // Should indicate wait time needed for 1 token at 1/sec
    if wait < 500*time.Millisecond {
        t.Errorf("Second Reserve() wait = %v, want >= 500ms", wait)
    }
}

func TestLimiterReserveN(t *testing.T) {
    // Very low rate (1 token per second), burst of 3
    limiter := New(1, 3)

    // Reserve 2 tokens - should be instant
    wait := limiter.ReserveN(2)
    if wait != 0 {
        t.Errorf("ReserveN(2) wait = %v, want 0", wait)
    }

    // 1 token remains, need 2 more
    wait = limiter.ReserveN(2)
    // Need 1 more token at 1/sec = ~1 second
    if wait < 500*time.Millisecond {
        t.Errorf("ReserveN(2) wait = %v, want >= 500ms", wait)
    }
}

func TestManagerAllowN(t *testing.T) {
    mgr := NewManager(10, 5)

    // Should allow burst of 5
    if !mgr.AllowN("key1", 5) {
        t.Error("AllowN(5) = false, want true")
    }

    // Should deny
    if mgr.AllowN("key1", 1) {
        t.Error("AllowN(1) after burst = true, want false")
    }
}

func TestManagerClear(t *testing.T) {
    mgr := NewManager(10, 3)

    // Exhaust limiter
    for i := 0; i < 3; i++ {
        mgr.Allow("key1")
    }
    mgr.Allow("key2")

    // Clear all
    mgr.Clear()

    // Both should work as new
    if !mgr.Allow("key1") || !mgr.Allow("key2") {
        t.Error("Allow() = false after Clear, want true")
    }
}

func TestTokensCappedAtBurst(t *testing.T) {
	// Create a limiter with high rate and small burst
	limiter := New(10000, 5)

	// Wait a bit for tokens to accumulate beyond burst
	time.Sleep(10 * time.Millisecond)

	// Tokens should be capped at burst (5)
	tokens := limiter.Tokens()
	if tokens > 5.0 {
		t.Errorf("Tokens() = %v, want <= 5.0 (burst cap)", tokens)
	}
	if tokens < 4.9 {
		t.Errorf("Tokens() = %v, want close to 5.0", tokens)
	}
}

func TestReserveNCappedAtBurst(t *testing.T) {
	// Create a limiter with very low rate and small burst
	limiter := New(1, 3)

	// Wait for tokens to try to accumulate beyond burst
	time.Sleep(10 * time.Millisecond)

	// ReserveN should cap tokens at burst before checking
	// Even after waiting, tokens should not exceed burst
	wait := limiter.ReserveN(3)
	if wait != 0 {
		t.Errorf("ReserveN(3) wait = %v, want 0", wait)
	}

	// Now all tokens consumed (at rate=1/s), next reserve should require wait
	wait = limiter.ReserveN(1)
	if wait == 0 {
		t.Errorf("ReserveN(1) after burst consumed wait = 0, want > 0")
	}
}

func TestAllowAtAllEventsExpired(t *testing.T) {
	sw := NewSlidingWindow(time.Second, 5)
	now := time.Now()

	// Add events in the past (all outside the window)
	sw.AllowAt(now.Add(-3 * time.Second))
	sw.AllowAt(now.Add(-2 * time.Second))
	sw.AllowAt(now.Add(-1500 * time.Millisecond))

	// All events are expired, so AllowAt should succeed
	// This tests the case where validIdx == len(events)
	if !sw.AllowAt(now) {
		t.Error("AllowAt(now) = false, want true (all previous events expired)")
	}
}

func TestSlidingWindowAllow(t *testing.T) {
    sw := NewSlidingWindow(time.Second, 3)

    // Should allow first 3
    for i := 0; i < 3; i++ {
        if !sw.Allow() {
            t.Errorf("Allow() = false at iteration %d, want true", i)
        }
    }

    // Should deny 4th
    if sw.Allow() {
        t.Error("Allow() = true after max events, want false")
    }
}

func TestSlidingWindowAllowAt(t *testing.T) {
    sw := NewSlidingWindow(time.Second, 2)
    now := time.Now()

    // Allow events at specific times
    if !sw.AllowAt(now) {
        t.Error("AllowAt(now) = false, want true")
    }
    if !sw.AllowAt(now.Add(100 * time.Millisecond)) {
        t.Error("AllowAt(now+100ms) = false, want true")
    }
    // 3rd event should be denied
    if sw.AllowAt(now.Add(200 * time.Millisecond)) {
        t.Error("AllowAt(now+200ms) = true, want false")
    }
}

func TestSlidingWindowCount(t *testing.T) {
    sw := NewSlidingWindow(time.Second, 5)
    now := time.Now()

    // Add events at different times
    sw.AllowAt(now.Add(-500 * time.Millisecond))
    sw.AllowAt(now.Add(-200 * time.Millisecond))
    sw.AllowAt(now.Add(-2 * time.Second)) // Outside window

    count := sw.Count()
    if count != 2 {
        t.Errorf("Count() = %d, want 2", count)
    }
}

func TestSlidingWindowReset(t *testing.T) {
    sw := NewSlidingWindow(time.Second, 2)

    sw.Allow()
    sw.Allow()

    // Should deny
    if sw.Allow() {
        t.Error("Allow() = true after max, want false")
    }

    // Reset
    sw.Reset()

    // Should allow again
    if !sw.Allow() {
        t.Error("Allow() = false after Reset, want true")
    }
}

func TestLastUpdate(t *testing.T) {
	before := time.Now()
	limiter := New(10, 5)
	limiter.Allow()
	after := time.Now()

	lu := limiter.LastUpdate()
	if lu.Before(before) || lu.After(after) {
		t.Errorf("LastUpdate() = %v, want between %v and %v", lu, before, after)
	}
}

func TestEvict(t *testing.T) {
	mgr := NewManager(10, 5)

	// Add two entries and access them
	mgr.Allow("old-key")
	mgr.Allow("new-key")

	// Manually set the lastUpdate of "old-key" to the past
	oldLimiter := mgr.Get("old-key")
	oldLimiter.mu.Lock()
	oldLimiter.lastUpdate = time.Now().Add(-20 * time.Minute)
	oldLimiter.mu.Unlock()

	// Evict entries older than 10 minutes
	evicted := mgr.Evict(10 * time.Minute)
	if evicted != 1 {
		t.Errorf("Evict() = %d, want 1", evicted)
	}

	// "old-key" should be gone (new limiter created on Get)
	newLimiter := mgr.Get("old-key")
	if newLimiter == oldLimiter {
		t.Error("Expected new limiter for evicted key")
	}

	// "new-key" should still be there
	newKeyLimiter := mgr.Get("new-key")
	if newKeyLimiter == nil {
		t.Error("new-key should still exist")
	}
}
