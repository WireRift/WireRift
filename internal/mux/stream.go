package mux

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
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
	ErrStreamClosed = errors.New("stream is closed")
	ErrStreamReset  = errors.New("stream was reset")
)

// initialReadBuffer is the receive buffer a stream starts with. It grows on
// demand up to the flow-control window, so a stream that has received nothing
// (or only a small request) does not pin a full window of memory: a peer can
// open thousands of streams, but pays for a window only by actually sending it.
const initialReadBuffer = 4096

// Stream represents a single bidirectional stream within a multiplexed connection.
// Stream implements io.ReadWriteCloser.
type Stream struct {
	id        uint32
	mux       *Mux
	readBuf   *ringBuffer
	readCh    chan struct{} // signals new data available
	window    atomic.Int32  // send window remaining
	maxWindow int32         // initial window; a peer can never credit more than this
	windowCh  chan struct{} // signals window update
	state     atomic.Int32
	closeOnce sync.Once

	// Half-close idle reaper (see Config.HalfCloseTimeout).
	lastActive atomic.Int64 // unix nanos of the last frame received
	idleTimer  atomic.Pointer[time.Timer]

	// Metadata (protected by metaMu)
	metaMu     sync.RWMutex
	remoteAddr string
	protocol   string
	tunnelID   string
}

// newStream creates a new stream.
func newStream(id uint32, m *Mux, windowSize int32) *Stream {
	s := &Stream{
		id:        id,
		mux:       m,
		readBuf:   newRingBuffer(min(int(windowSize), initialReadBuffer)),
		readCh:    make(chan struct{}, 1),
		windowCh:  make(chan struct{}, 1),
		maxWindow: windowSize,
	}
	s.window.Store(windowSize)
	return s
}

// ID returns the stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// Protocol returns the protocol (http, tcp, etc.).
func (s *Stream) Protocol() string {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.protocol
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
	muxDone := false
	for {
		// Observe the state before draining the buffer: if the remote has
		// already closed, any data it sent is guaranteed to be buffered by now,
		// so an empty buffer after this point really means EOF.
		state := s.state.Load()

		n, _ = s.readFromBuffer(p)
		if n > 0 {
			return n, nil
		}

		if state == streamStateClosed || state == streamStateHalfClosedRemote {
			return 0, io.EOF
		}
		if state == streamStateReset {
			return 0, ErrStreamReset
		}

		if muxDone {
			// The connection died before the peer finished this stream. That is
			// a truncation, not a normal end: reporting io.EOF would let a
			// close-delimited response or a TCP tunnel look complete.
			return 0, io.ErrUnexpectedEOF
		}

		// Wait for data
		select {
		case <-s.readCh:
			// Data available, continue loop
		case <-s.mux.done:
			// Go round once more: data and a peer close may have landed just
			// before the connection went away.
			muxDone = true
		}
	}
}

// readFromBuffer reads from the internal buffer and sends window update.
func (s *Stream) readFromBuffer(p []byte) (int, error) {
	n, _ := s.readBuf.Read(p)
	if n > 0 {
		// Send window update
		if err := s.mux.sendWindowUpdate(s.id, uint32(n)); err != nil { //nolint:gosec // n <= len(buffer) <= 16 MB
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
		// Recheck state on each iteration to detect close/reset during write
		state = s.state.Load()
		if state == streamStateClosed || state == streamStateHalfClosedLocal {
			return total, ErrStreamClosed
		}
		if state == streamStateReset {
			return total, ErrStreamReset
		}

		// Reserve send credit before the frame goes out. Debiting afterwards
		// let a fast peer's window update arrive first, get clamped to
		// maxWindow, and lose that credit for good; it also let concurrent
		// writers overdraw the window.
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
		if !s.window.CompareAndSwap(window, window-int32(chunk)) { //nolint:gosec // chunk <= window (int32)
			continue // window changed under us; recompute
		}
		// windowCh holds one token, so one update wakes one blocked writer. If
		// credit is left over, pass the wake-up on to the next writer.
		if s.window.Load() > 0 {
			s.signalWindow()
		}

		// Send data frame
		if err := s.mux.sendDataFrame(s.id, p[total:total+chunk]); err != nil {
			s.window.Add(int32(chunk)) //nolint:gosec // refund the reservation
			s.signalWindow()
			return total, err
		}

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
		// Re-read: the remote may have closed concurrently.
		final := s.state.Load()
		fullyClosed := final == streamStateClosed || final == streamStateReset

		// Send close frame (non-blocking, ignore error if mux is closed)
		select {
		case <-s.mux.done:
			// Mux closed, can't send
		default:
			err = s.mux.sendStreamClose(s.id)
		}

		// Keep a half-closed stream registered so the remote can still
		// deliver its remaining data (half-close semantics); it is removed
		// once the remote side closes as well.
		if fullyClosed {
			s.cleanup()
		} else if final == streamStateHalfClosedLocal {
			s.armIdleReaper()
		}
	})
	return err
}

// armIdleReaper resets a stream whose local side is closed and whose remote
// side has sent nothing for Config.HalfCloseTimeout, so a peer that never
// closes its side cannot pin the stream until the mux dies. Any frame from the
// peer postpones the reset.
func (s *Stream) armIdleReaper() {
	d := s.mux.config.HalfCloseTimeout
	if d <= 0 {
		return
	}
	s.lastActive.Store(time.Now().UnixNano())
	var fire func()
	fire = func() {
		if s.state.Load() != streamStateHalfClosedLocal {
			return
		}
		idle := time.Since(time.Unix(0, s.lastActive.Load()))
		if idle < d {
			if t := s.idleTimer.Load(); t != nil {
				t.Reset(d - idle)
			}
			return
		}
		_ = s.Reset()
	}
	s.idleTimer.Store(time.AfterFunc(d, fire))
}

// Reset immediately aborts the stream.
func (s *Stream) Reset() error {
	s.state.Store(streamStateReset)

	// Wake local readers and writers blocked on this stream: they must see the
	// reset now, not whenever the peer happens to send something.
	s.wake()

	// Send reset frame (non-blocking, ignore error if mux is closed)
	select {
	case <-s.mux.done:
		// Mux closed, can't send
	default:
		_ = s.mux.sendStreamReset(s.id)
	}

	s.cleanup()
	return nil
}

// cleanup releases resources.
func (s *Stream) cleanup() {
	if t := s.idleTimer.Load(); t != nil {
		t.Stop()
	}
	s.mux.removeStream(s.id)
}

// onDataFrame handles incoming data.
func (s *Stream) onDataFrame(data []byte) error {
	s.lastActive.Store(time.Now().UnixNano())
	// A conforming peer never has more than one window of unread data in
	// flight; anything beyond that is a protocol violation, not data to drop.
	if s.readBuf.Len()+len(data) > int(s.maxWindow) {
		s.onResetFrame()
		_ = s.mux.sendStreamReset(s.id)
		s.cleanup()
		return nil
	}
	s.readBuf.Write(data) //nolint:errcheck // ringBuffer.Write never fails

	// Signal data available
	select {
	case s.readCh <- struct{}{}:
	default:
	}

	return nil
}

// onWindowUpdate handles window update.
func (s *Stream) onWindowUpdate(delta uint32) {
	s.lastActive.Store(time.Now().UnixNano())
	// Saturating add: a hostile peer must not be able to wrap the window
	// negative (stalling the stream) or inflate it without bound.
	limit := int64(s.maxWindow)
	for {
		cur := s.window.Load()
		next := int64(cur) + int64(delta)
		if next > limit {
			next = limit
		}
		if s.window.CompareAndSwap(cur, int32(next)) { //nolint:gosec // next clamped to maxWindow (int32)
			break
		}
	}

	s.signalWindow()
}

// signalWindow wakes a writer waiting for send credit (non-blocking).
func (s *Stream) signalWindow() {
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
		if s.state.CompareAndSwap(streamStateHalfClosedLocal, streamStateClosed) {
			defer s.cleanup()
		}
	}

	// Signal EOF to readers
	select {
	case s.readCh <- struct{}{}:
	default:
	}
}

// wake signals blocked readers and writers to re-check the stream state.
func (s *Stream) wake() {
	select {
	case s.readCh <- struct{}{}:
	default:
	}
	select {
	case s.windowCh <- struct{}{}:
	default:
	}
}

// onResetFrame handles reset frame from remote.
func (s *Stream) onResetFrame() {
	s.state.Store(streamStateReset)
	defer s.cleanup()
	s.wake()
}

// onMuxClosed is called when the whole connection goes away. A stream whose
// peer already finished sending keeps its end-of-stream state, so the data it
// received can still be read and then ends in a clean EOF; any other stream was
// cut off and is reset.
func (s *Stream) onMuxClosed() {
	for {
		state := s.state.Load()
		if state == streamStateHalfClosedRemote || state == streamStateClosed || state == streamStateReset {
			defer s.cleanup()
			s.wake()
			return
		}
		if s.state.CompareAndSwap(state, streamStateReset) {
			defer s.cleanup()
			s.wake()
			return
		}
	}
}

// IsClosed returns true if the stream is fully closed.
func (s *Stream) IsClosed() bool {
	state := s.state.Load()
	return state == streamStateClosed || state == streamStateReset
}
