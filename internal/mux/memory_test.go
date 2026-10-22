package mux

import (
	"net"
	"testing"
)

// A stream that has received nothing must not pin a full flow-control window:
// a peer can open thousands of streams cheaply, so memory is paid for only when
// data actually arrives.
func TestNewStreamDoesNotPreallocateWindow(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	m := New(c1, DefaultConfig())

	s := newStream(2, m, m.config.WindowSize)
	if got := len(s.readBuf.buf); got > initialReadBuffer {
		t.Errorf("idle stream holds a %d byte buffer, want <= %d (window is %d)", got, initialReadBuffer, m.config.WindowSize)
	}
	if s.maxWindow != m.config.WindowSize {
		t.Errorf("flow-control window changed to %d, want %d", s.maxWindow, m.config.WindowSize)
	}
}

// The buffer still grows to carry a full window of unread data.
func TestStreamBufferGrowsToFullWindow(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	m := New(c1, DefaultConfig())
	s := newStream(2, m, m.config.WindowSize)

	chunk := make([]byte, 16*1024)
	for sent := int32(0); sent < m.config.WindowSize; sent += int32(len(chunk)) {
		if err := s.onDataFrame(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.readBuf.Len(); got != int(m.config.WindowSize) {
		t.Errorf("buffered %d bytes, want the full window %d", got, m.config.WindowSize)
	}
}

// A window above what the receive buffer can hold would silently drop data.
func TestWindowSizeClampedToBufferLimit(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	cfg := DefaultConfig()
	cfg.WindowSize = 64 * 1024 * 1024
	m := New(c1, cfg)
	if m.config.WindowSize != maxRingBufferSize {
		t.Errorf("WindowSize = %d, want it clamped to %d", m.config.WindowSize, maxRingBufferSize)
	}
}
