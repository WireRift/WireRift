package ratelimit

import (
	"sync"
	"time"
)

// Limiter implements a token bucket rate limiter.
type Limiter struct {
	rate       float64   // tokens per second
	burst      int       // maximum burst size
	tokens     float64   // current tokens
	lastUpdate time.Time // last time tokens were updated
	mu         sync.Mutex
}

// New creates a new rate limiter.
// rate is the number of tokens added per second.
// burst is the maximum number of tokens that can accumulate.
func New(rate float64, burst int) *Limiter {
	return &Limiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Allow attempts to take one token. Returns true if successful.
func (l *Limiter) Allow() bool {
	return l.AllowN(1)
}

// AllowN attempts to take n tokens. Returns true if successful.
func (l *Limiter) AllowN(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()
	l.lastUpdate = now

	// Add tokens based on elapsed time
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}

	// Check if we have enough tokens
	if l.tokens >= float64(n) {
		l.tokens -= float64(n)
		return true
	}

	return false
}

// Wait blocks until a token is available.
func (l *Limiter) Wait() {
	l.WaitN(1)
}

// WaitN blocks until n tokens are available.
func (l *Limiter) WaitN(n int) {
	for {
		if l.AllowN(n) {
			return
		}
		// Sleep a short time before retrying
		time.Sleep(time.Millisecond * 10)
	}
}

// Reserve reserves a token without consuming it.
// Returns the duration to wait before the reservation can be used.
func (l *Limiter) Reserve() time.Duration {
	return l.ReserveN(1)
}

// ReserveN reserves n tokens without consuming them.
func (l *Limiter) ReserveN(n int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()
	l.lastUpdate = now

	// Add tokens
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}

	// Calculate wait time
	if l.tokens >= float64(n) {
		l.tokens -= float64(n)
		return 0
	}

	deficit := float64(n) - l.tokens
	waitDuration := time.Duration(deficit / l.rate * float64(time.Second))

	return waitDuration
}

// Rate returns the current rate.
func (l *Limiter) Rate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// Burst returns the burst size.
func (l *Limiter) Burst() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.burst
}

// SetRate updates the rate.
func (l *Limiter) SetRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = rate
}

// LastUpdate returns the last time this limiter was accessed.
func (l *Limiter) LastUpdate() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastUpdate
}

// Tokens returns the current number of tokens.
func (l *Limiter) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()

	tokens := l.tokens + elapsed*l.rate
	if tokens > float64(l.burst) {
		tokens = float64(l.burst)
	}

	return tokens
}

// Manager manages multiple rate limiters.
type Manager struct {
	limiters sync.Map // map[string]*Limiter
	rate     float64
	burst    int
}

// NewManager creates a new rate limiter manager.
func NewManager(rate float64, burst int) *Manager {
	return &Manager{
		rate:  rate,
		burst: burst,
	}
}

// Get returns the rate limiter for the given key.
// Creates a new limiter if it doesn't exist.
func (m *Manager) Get(key string) *Limiter {
	if v, ok := m.limiters.Load(key); ok {
		return v.(*Limiter)
	}

	limiter := New(m.rate, m.burst)
	actual, _ := m.limiters.LoadOrStore(key, limiter)
	return actual.(*Limiter)
}

// AllowWith is Allow for a key that has its own rate and burst instead of the
// manager's defaults. The parameters apply when the limiter is first created.
func (m *Manager) AllowWith(key string, rate float64, burst int) bool {
	if v, ok := m.limiters.Load(key); ok {
		return v.(*Limiter).Allow()
	}
	actual, _ := m.limiters.LoadOrStore(key, New(rate, burst))
	return actual.(*Limiter).Allow()
}

// Allow checks if the key is allowed.
func (m *Manager) Allow(key string) bool {
	return m.Get(key).Allow()
}

// AllowN checks if the key is allowed for n tokens.
func (m *Manager) AllowN(key string, n int) bool {
	return m.Get(key).AllowN(n)
}

// Remove removes a rate limiter.
func (m *Manager) Remove(key string) {
	m.limiters.Delete(key)
}

// Clear removes all rate limiters.
func (m *Manager) Clear() {
	m.limiters.Range(func(key, _ any) bool {
		m.limiters.Delete(key)
		return true
	})
}

// Evict removes limiters that have not been accessed for the given duration.
// This prevents unbounded growth of the limiters map from unique client IPs.
func (m *Manager) Evict(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	evicted := 0
	m.limiters.Range(func(key, value any) bool {
		limiter := value.(*Limiter)
		if limiter.LastUpdate().Before(cutoff) {
			m.limiters.Delete(key)
			evicted++
		}
		return true
	})
	return evicted
}
