package mux

import (
	"errors"
	"sync"
)

// Errors returned by ringBuffer operations.
var (
	ErrBufferFull  = errors.New("buffer is full")
	ErrBufferEmpty = errors.New("buffer is empty")
)

// maxRingBufferSize is the maximum size a ring buffer can grow to (16 MB).
const maxRingBufferSize = 16 * 1024 * 1024

// ringBuffer is a circular buffer for stream data.
// It is safe for concurrent use with proper locking.
type ringBuffer struct {
	buf     []byte
	size    int
	maxSize int
	r       int // read cursor
	w       int // write cursor
	full    bool
	mu      sync.Mutex
}

// newRingBuffer creates a new ring buffer with the given initial size.
func newRingBuffer(size int) *ringBuffer {
	if size <= 0 {
		size = 4096
	}
	return &ringBuffer{
		buf:     make([]byte, size),
		size:    size,
		maxSize: maxRingBufferSize,
	}
}

// Write copies data into the buffer. Returns the number of bytes written.
// If the buffer is full, it writes as much as possible.
func (rb *ringBuffer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Check if we need to grow
	available := rb.availableLocked()
	if available < len(data) {
		// Grow buffer to fit data (up to maxSize)
		newSize := rb.size + len(data) - available
		if newSize > rb.maxSize {
			newSize = rb.maxSize
		}
		if newSize > rb.size {
			rb.growLocked(newSize)
		}
	}

	n := 0
	for n < len(data) && !rb.full {
		rb.buf[rb.w] = data[n]
		rb.w = (rb.w + 1) % rb.size
		n++
		rb.full = rb.r == rb.w
	}

	return n, nil
}

// Read copies data from the buffer into p. Returns the number of bytes read.
// If the buffer is empty, returns 0, nil.
func (rb *ringBuffer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.isEmptyLocked() {
		return 0, nil
	}

	n := 0
	for n < len(p) && !rb.isEmptyLocked() {
		p[n] = rb.buf[rb.r]
		rb.r = (rb.r + 1) % rb.size
		n++
		rb.full = false
	}

	return n, nil
}

// Len returns the number of bytes currently in the buffer.
func (rb *ringBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.lenLocked()
}

// Available returns the number of bytes that can be written.
func (rb *ringBuffer) Available() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.availableLocked()
}

// Reset clears the buffer.
func (rb *ringBuffer) Reset() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.r = 0
	rb.w = 0
	rb.full = false
}

// growLocked grows the buffer to the new size. Must be called with lock held.
func (rb *ringBuffer) growLocked(newSize int) {
	if newSize <= rb.size {
		return
	}

	// Capture current data length before modifying state
	dataLen := rb.lenLocked()

	// Allocate new buffer
	newBuf := make([]byte, newSize)

	// Copy existing data
	if dataLen > 0 {
		if rb.w > rb.r {
			copy(newBuf, rb.buf[rb.r:rb.w])
		} else {
			n := copy(newBuf, rb.buf[rb.r:])
			copy(newBuf[n:], rb.buf[:rb.w])
		}
	}

	rb.buf = newBuf
	rb.size = newSize
	rb.r = 0
	rb.w = dataLen
	rb.full = rb.w == rb.size
}

// lenLocked returns the number of bytes in the buffer. Must be called with lock held.
func (rb *ringBuffer) lenLocked() int {
	if rb.full {
		return rb.size
	}
	if rb.w >= rb.r {
		return rb.w - rb.r
	}
	return rb.size - rb.r + rb.w
}

// availableLocked returns the available space. Must be called with lock held.
func (rb *ringBuffer) availableLocked() int {
	if rb.full {
		return 0
	}
	if rb.w >= rb.r {
		return rb.size - rb.w + rb.r
	}
	return rb.r - rb.w
}

// isEmptyLocked returns true if buffer is empty. Must be called with lock held.
func (rb *ringBuffer) isEmptyLocked() bool {
	return !rb.full && rb.r == rb.w
}
