package ratelimit

import (
	"sync"
	"time"
)

// Limiter implements a token bucket rate limiter.
type Limiter struct {
	rate       float64       // tokens per second
	burst      int           // maximum burst size
	tokens     float64       // current tokens
	lastUpdate time.Time     // last time tokens were updated
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
	waitDuration := time.Duration(deficit/l.rate) * time.Second

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
	m.limiters.Range(func(key, value any) bool {
		m.limiters.Delete(key)
		return true
	})
}

// SlidingWindow implements a sliding window rate limiter.
type SlidingWindow struct {
	windowSize time.Duration
	maxEvents  int
	events     []time.Time
	mu         sync.Mutex
}

// NewSlidingWindow creates a new sliding window rate limiter.
func NewSlidingWindow(windowSize time.Duration, maxEvents int) *SlidingWindow {
	return &SlidingWindow{
		windowSize: windowSize,
		maxEvents:  maxEvents,
		events:     make([]time.Time, 0, maxEvents),
	}
}

// Allow checks if an event is allowed.
func (s *SlidingWindow) Allow() bool {
	return s.AllowAt(time.Now())
}

// AllowAt checks if an event at a specific time is allowed.
func (s *SlidingWindow) AllowAt(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove old events
	cutoff := now.Add(-s.windowSize)
	validIdx := 0
	for i, t := range s.events {
		if t.After(cutoff) {
			validIdx = i
			break
		}
		validIdx = i + 1
	}
	s.events = s.events[validIdx:]

	// Check if we can add a new event
	if len(s.events) >= s.maxEvents {
		return false
	}

	s.events = append(s.events, now)
	return true
}

// Count returns the number of events in the current window.
func (s *SlidingWindow) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-s.windowSize)

	count := 0
	for _, t := range s.events {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// Reset clears all events.
func (s *SlidingWindow) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = s.events[:0]
}
