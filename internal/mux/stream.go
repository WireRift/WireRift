package mux

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Stream states.
const (
	streamStateActive int32 = iota
	streamStateHalfClosedLocal
	streamStateHalfClosedRemote
	streamStateClosed
	streamStateReset
)

// Errors returned by Stream operations.
var (
	ErrStreamClosed    = errors.New("stream is closed")
	ErrStreamReset     = errors.New("stream was reset")
	ErrInvalidStreamID = errors.New("invalid stream ID")
)

// Stream represents a single bidirectional stream within a multiplexed connection.
// Stream implements io.ReadWriteCloser.
type Stream struct {
	id       uint32
	mux      *Mux
	readBuf  *ringBuffer
	readCh   chan struct{} // signals new data available
	window   atomic.Int32  // send window remaining
	windowCh chan struct{} // signals window update
	state    atomic.Int32
	closeOnce sync.Once

	// Metadata (protected by metaMu)
	metaMu     sync.RWMutex
	remoteAddr string
	protocol   string
	tunnelID   string

	// Callbacks
	onClose func()
}

// newStream creates a new stream.
func newStream(id uint32, m *Mux, windowSize int32) *Stream {
	s := &Stream{
		id:       id,
		mux:      m,
		readBuf:  newRingBuffer(int(windowSize)),
		readCh:   make(chan struct{}, 1),
		windowCh: make(chan struct{}, 1),
	}
	s.window.Store(windowSize)
	return s
}

// ID returns the stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// RemoteAddr returns the remote address of the connection.
func (s *Stream) RemoteAddr() string {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.remoteAddr
}

// Protocol returns the protocol (http, tcp, etc.).
func (s *Stream) Protocol() string {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.protocol
}

// LocalAddr returns the local address (delegates to mux).
func (s *Stream) LocalAddr() net.Addr {
	if s.mux != nil {
		return s.mux.LocalAddr()
	}
	return nil
}

// TunnelID returns the tunnel ID associated with this stream.
func (s *Stream) TunnelID() string {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.tunnelID
}

// SetMetadata sets stream metadata.
func (s *Stream) SetMetadata(remoteAddr, protocol, tunnelID string) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	s.remoteAddr = remoteAddr
	s.protocol = protocol
	s.tunnelID = tunnelID
}

// Read reads data from the stream. Blocks until data is available or stream is closed.
func (s *Stream) Read(p []byte) (n int, err error) {
	for {
		// Try to read from buffer
		n, _ = s.readFromBuffer(p)
		if n > 0 {
			return n, nil
		}

		// Check state
		state := s.state.Load()
		if state == streamStateClosed || state == streamStateHalfClosedRemote {
			return 0, io.EOF
		}
		if state == streamStateReset {
			return 0, ErrStreamReset
		}

		// Wait for data
		select {
		case <-s.readCh:
			// Data available, continue loop
		case <-s.mux.done:
			return 0, io.EOF
		}
	}
}

// readFromBuffer reads from the internal buffer and sends window update.
func (s *Stream) readFromBuffer(p []byte) (int, error) {
	n, _ := s.readBuf.Read(p)
	if n > 0 {
		// Send window update
		if err := s.mux.sendWindowUpdate(s.id, uint32(n)); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Write writes data to the stream.
func (s *Stream) Write(p []byte) (n int, err error) {
	state := s.state.Load()
	if state == streamStateClosed || state == streamStateHalfClosedLocal {
		return 0, ErrStreamClosed
	}
	if state == streamStateReset {
		return 0, ErrStreamReset
	}

	// Wait for window availability
	total := 0
	for total < len(p) {
		// Check how much we can send
		window := s.window.Load()
		if window <= 0 {
			// Wait for window update
			select {
			case <-s.windowCh:
				continue
			case <-s.mux.done:
				return total, io.EOF
			}
		}

		// Calculate chunk size
		chunk := len(p) - total
		if chunk > int(window) {
			chunk = int(window)
		}
		if chunk > s.mux.maxFrameSize {
			chunk = s.mux.maxFrameSize
		}

		// Send data frame
		if err := s.mux.sendDataFrame(s.id, p[total:total+chunk]); err != nil {
			return total, err
		}

		s.window.Add(-int32(chunk))
		total += chunk
	}

	return total, nil
}

// Close closes the stream for writing. It does not close the read side.
func (s *Stream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		state := s.state.Load()
		if state == streamStateActive {
			s.state.CompareAndSwap(streamStateActive, streamStateHalfClosedLocal)
		} else if state == streamStateHalfClosedRemote {
			s.state.CompareAndSwap(streamStateHalfClosedRemote, streamStateClosed)
		}

		// Send close frame (non-blocking, ignore error if mux is closed)
		select {
		case <-s.mux.done:
			// Mux closed, can't send
		default:
			err = s.mux.sendStreamClose(s.id)
		}

		// Cleanup
		s.cleanup()
	})
	return err
}

// CloseRead closes the read side of the stream.
func (s *Stream) CloseRead() error {
	state := s.state.Load()
	if state == streamStateActive {
		s.state.CompareAndSwap(streamStateActive, streamStateHalfClosedRemote)
	} else if state == streamStateHalfClosedLocal {
		s.state.CompareAndSwap(streamStateHalfClosedLocal, streamStateClosed)
	}
	return nil
}

// Reset immediately aborts the stream.
func (s *Stream) Reset() error {
	s.state.Store(streamStateReset)

	// Send reset frame (non-blocking, ignore error if mux is closed)
	select {
	case <-s.mux.done:
		// Mux closed, can't send
	default:
		s.mux.sendStreamReset(s.id)
	}

	s.cleanup()
	return nil
}

// cleanup releases resources.
func (s *Stream) cleanup() {
	if s.onClose != nil {
		s.onClose()
	}
	s.mux.removeStream(s.id)
}

// onDataFrame handles incoming data.
func (s *Stream) onDataFrame(data []byte) error {
	// ringBuffer.Write always returns nil error
	s.readBuf.Write(data)

	// Signal data available
	select {
	case s.readCh <- struct{}{}:
	default:
	}

	return nil
}

// onWindowUpdate handles window update.
func (s *Stream) onWindowUpdate(delta uint32) {
	s.window.Add(int32(delta))

	// Signal window available
	select {
	case s.windowCh <- struct{}{}:
	default:
	}
}

// onCloseFrame handles close frame from remote.
func (s *Stream) onCloseFrame() {
	state := s.state.Load()
	if state == streamStateActive {
		s.state.CompareAndSwap(streamStateActive, streamStateHalfClosedRemote)
	} else if state == streamStateHalfClosedLocal {
		s.state.CompareAndSwap(streamStateHalfClosedLocal, streamStateClosed)
	}

	// Signal EOF to readers
	select {
	case s.readCh <- struct{}{}:
	default:
	}
}

// onResetFrame handles reset frame from remote.
func (s *Stream) onResetFrame() {
	s.state.Store(streamStateReset)

	// Signal to readers/writers
	select {
	case s.readCh <- struct{}{}:
	default:
	}
	select {
	case s.windowCh <- struct{}{}:
	default:
	}
}

// IsClosed returns true if the stream is fully closed.
func (s *Stream) IsClosed() bool {
	state := s.state.Load()
	return state == streamStateClosed || state == streamStateReset
}
