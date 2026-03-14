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
