package mux

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// Errors returned by Mux operations.
var (
	ErrMuxClosed      = errors.New("multiplexer is closed")
	ErrTooManyStreams = errors.New("too many active streams")
)

// Config holds multiplexer configuration.
type Config struct {
	// MaxStreams is the maximum number of concurrent streams.
	MaxStreams int

	// WindowSize is the initial flow control window size.
	WindowSize int32

	// MaxFrameSize is the maximum frame payload size.
	MaxFrameSize int

	// HeartbeatInterval is the interval between heartbeats.
	HeartbeatInterval time.Duration

	// WriteTimeout bounds one write to the connection. A peer that stops
	// reading would otherwise hold the frame writer (and with it every stream
	// and the read loop's heartbeat replies) until the session times out; when
	// a write times out the connection is closed, since a partly written frame
	// cannot be recovered. Zero means DefaultWriteTimeout, negative disables it.
	WriteTimeout time.Duration
}

// DefaultWriteTimeout is the WriteTimeout used when the config leaves it zero.
const DefaultWriteTimeout = 60 * time.Second

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		MaxStreams:        10000,
		WindowSize:        proto.DefaultWindowSize,
		MaxFrameSize:      64 * 1024, // 64 KB
		HeartbeatInterval: 30 * time.Second,
		WriteTimeout:      DefaultWriteTimeout,
	}
}

// SetMaxStreams changes the concurrent stream limit. A server sets 0 until the
// peer has authenticated, so an unauthenticated peer cannot open streams.
func (m *Mux) SetMaxStreams(n int) {
	m.maxStreams.Store(int64(n))
}

// Mux is a stream multiplexer that carries multiple streams over a single connection.
type Mux struct {
	conn        net.Conn
	frameWriter *proto.FrameWriter
	frameReader *proto.FrameReader
	config      Config

	streams sync.Map // map[uint32]*Stream

	// idMu guards nextID and makes "pick a free ID + register the stream" atomic.
	idMu   sync.Mutex
	nextID uint32

	accept    chan *Stream      // incoming streams from remote
	controlCh chan *proto.Frame // control frames (auth, tunnel)
	done      chan struct{}
	err       atomic.Value // error that caused shutdown

	streamCount   atomic.Int32 // number of registered streams
	maxStreams    atomic.Int64 // current stream limit (see SetMaxStreams)
	lastHeartbeat atomic.Int64 // unix nano of last heartbeat ack

	maxFrameSize int

	mu sync.Mutex
}

// New creates a new multiplexer.
func New(conn net.Conn, config Config) *Mux {
	if config.MaxStreams <= 0 {
		config.MaxStreams = 10000
	}
	if config.WindowSize <= 0 {
		config.WindowSize = proto.DefaultWindowSize
	}
	if config.WindowSize > maxRingBufferSize {
		config.WindowSize = maxRingBufferSize // the receive buffer cannot hold more
	}
	if config.MaxFrameSize <= 0 {
		config.MaxFrameSize = 64 * 1024
	}

	if config.WriteTimeout == 0 {
		config.WriteTimeout = DefaultWriteTimeout
	}

	m := &Mux{
		conn:         conn,
		frameReader:  proto.NewFrameReader(conn),
		config:       config,
		accept:       make(chan *Stream, 128),
		controlCh:    make(chan *proto.Frame, 16),
		done:         make(chan struct{}),
		maxFrameSize: config.MaxFrameSize,
	}
	m.frameWriter = proto.NewFrameWriter(&deadlineWriter{m: m})
	m.maxStreams.Store(int64(config.MaxStreams))
	m.nextID = 2 // Start at 2 to avoid collision with ControlStreamID (0)

	return m
}

// deadlineWriter writes to the mux's connection with the configured write
// timeout and shuts the mux down on a failed write.
type deadlineWriter struct{ m *Mux }

func (w *deadlineWriter) Write(p []byte) (int, error) {
	m := w.m
	if m.config.WriteTimeout > 0 {
		_ = m.conn.SetWriteDeadline(time.Now().Add(m.config.WriteTimeout))
	}
	n, err := m.conn.Write(p)
	if err != nil && n < len(p) {
		// The frame may be cut in the middle: the connection is unusable. Close
		// asynchronously, the caller may hold locks the shutdown needs.
		go func() { _ = m.closeWithError(err) }()
	}
	return n, err
}

// OpenStream opens a new stream.
func (m *Mux) OpenStream() (*Stream, error) {
	select {
	case <-m.done:
		return nil, ErrMuxClosed
	default:
	}

	if int(m.streamCount.Load()) >= int(m.maxStreams.Load()) {
		return nil, ErrTooManyStreams
	}

	m.idMu.Lock()
	defer m.idMu.Unlock()

	id, ok := m.allocIDLocked()
	if !ok {
		return nil, ErrTooManyStreams
	}
	stream := newStream(id, m, m.config.WindowSize)
	m.addStream(stream)

	return stream, nil
}

// maxLocalStreamID is the largest ID OpenStream hands out: IDs are even (the
// opener's half of the ID space) and fit the 3-byte frame field.
const maxLocalStreamID = proto.MaxStreamID &^ 1

// allocIDLocked returns the next free even stream ID. IDs are handed out round
// the whole 24-bit space and skip ones that are still live, so a long-lived
// session never runs out: an ID is reused only after ~8.4M other opens, long
// after any frame still in flight for its previous stream (all frames share one
// ordered connection) has been delivered. idMu must be held.
func (m *Mux) allocIDLocked() (uint32, bool) {
	// More live streams than this cannot exist, so the scan always ends.
	for tries := 0; tries <= int(m.maxStreams.Load())+1; tries++ {
		id := m.nextID
		if id < 2 || id > maxLocalStreamID {
			id = 2 // wrapped
		}
		m.nextID = id + 2
		if _, live := m.streams.Load(id); !live {
			return id, true
		}
	}
	return 0, false
}

// AcceptStream waits for and returns the next incoming stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	select {
	case stream := <-m.accept:
		return stream, nil
	case <-m.done:
		return nil, io.EOF
	}
}

// Close closes the multiplexer and all streams.
func (m *Mux) Close() error {
	return m.closeWithError(ErrMuxClosed)
}

// closeWithError closes the mux with a specific error.
func (m *Mux) closeWithError(err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case <-m.done:
		return nil
	default:
	}

	m.err.Store(err)
	close(m.done)

	// Close all streams
	m.streams.Range(func(key, value any) bool {
		if stream, ok := value.(*Stream); ok {
			stream.onMuxClosed()
		}
		return true
	})

	return m.conn.Close()
}

// Done returns a channel that is closed when the mux is shut down.
func (m *Mux) Done() <-chan struct{} {
	return m.done
}

// Err returns the error that caused the mux to shut down.
func (m *Mux) Err() error {
	if v := m.err.Load(); v != nil {
		if err, ok := v.(error); ok {
			return err
		}
	}
	return nil
}

// LocalAddr returns the local address.
func (m *Mux) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (m *Mux) RemoteAddr() net.Addr {
	return m.conn.RemoteAddr()
}

// GetFrameWriter returns the frame writer for sending frames.
func (m *Mux) GetFrameWriter() *proto.FrameWriter {
	return m.frameWriter
}

// GetFrameReader returns the frame reader for receiving frames.
func (m *Mux) GetFrameReader() *proto.FrameReader {
	return m.frameReader
}

// Run starts the multiplexer's read loop. It blocks until the connection is closed.
func (m *Mux) Run() error {
	for {
		frame, err := m.frameReader.Read()
		if err != nil {
			return m.closeWithError(err)
		}

		if err := m.handleFrame(frame); err != nil {
			return m.closeWithError(err)
		}
	}
}

// handleFrame dispatches a frame to the appropriate handler.
func (m *Mux) handleFrame(frame *proto.Frame) error {
	switch frame.Type {
	case proto.FrameStreamOpen:
		return m.handleStreamOpen(frame)
	case proto.FrameStreamData:
		return m.handleStreamData(frame)
	case proto.FrameStreamClose:
		return m.handleStreamClose(frame)
	case proto.FrameStreamRst:
		return m.handleStreamRst(frame)
	case proto.FrameStreamWindow:
		return m.handleStreamWindow(frame)
	case proto.FrameHeartbeat:
		return m.handleHeartbeat(frame)
	case proto.FrameHeartbeatAck:
		return m.handleHeartbeatAck(frame)
	case proto.FrameGoAway:
		return m.handleGoAway(frame)
	case proto.FrameError:
		return m.handleError(frame)
	case proto.FrameAuthReq, proto.FrameAuthRes, proto.FrameTunnelReq, proto.FrameTunnelRes, proto.FrameTunnelClose:
		return m.handleControlFrame(frame)
	default:
		// Unknown frame type - ignore
		return nil
	}
}

// handleControlFrame routes control frames (auth, tunnel) to the control channel.
func (m *Mux) handleControlFrame(frame *proto.Frame) error {
	select {
	case <-m.done:
		return ErrMuxClosed
	default:
	}

	select {
	case m.controlCh <- frame:
		return nil
	case <-m.done:
		return ErrMuxClosed
	}
}

// ControlFrame returns the channel for receiving control frames (auth, tunnel).
func (m *Mux) ControlFrame() <-chan *proto.Frame {
	return m.controlCh
}

// handleStreamOpen handles a STREAM_OPEN frame.
func (m *Mux) handleStreamOpen(frame *proto.Frame) error {
	var msg proto.StreamOpen
	if err := proto.DecodeJSONPayload(frame, &msg); err != nil {
		return err
	}

	// Reject IDs that would clobber a live stream, the control stream, and
	// opens beyond the configured concurrency limit.
	if frame.StreamID == proto.ControlStreamID || int(m.streamCount.Load()) >= int(m.maxStreams.Load()) {
		_ = m.sendStreamReset(frame.StreamID)
		return nil
	}
	if _, exists := m.streams.Load(frame.StreamID); exists {
		_ = m.sendStreamReset(frame.StreamID)
		return nil
	}

	stream := newStream(frame.StreamID, m, m.config.WindowSize)
	stream.SetMetadata(msg.RemoteAddr, msg.Protocol, msg.TunnelID)
	m.addStream(stream)

	// Notify acceptor
	select {
	case m.accept <- stream:
	default:
		// Accept queue full, reset stream
		_ = stream.Reset()
	}

	return nil
}

// handleStreamData handles a STREAM_DATA frame.
func (m *Mux) handleStreamData(frame *proto.Frame) error {
	stream, ok := m.getStream(frame.StreamID)
	if !ok {
		// Stream not found, send reset
		_ = m.sendStreamReset(frame.StreamID)
		return nil
	}

	return stream.onDataFrame(frame.Payload)
}

// handleStreamClose handles a STREAM_CLOSE frame.
func (m *Mux) handleStreamClose(frame *proto.Frame) error {
	stream, ok := m.getStream(frame.StreamID)
	if !ok {
		return nil
	}

	stream.onCloseFrame()
	return nil
}

// handleStreamRst handles a STREAM_RST frame.
func (m *Mux) handleStreamRst(frame *proto.Frame) error {
	stream, ok := m.getStream(frame.StreamID)
	if !ok {
		return nil
	}

	stream.onResetFrame()
	return nil
}

// handleStreamWindow handles a STREAM_WINDOW frame.
func (m *Mux) handleStreamWindow(frame *proto.Frame) error {
	var msg proto.StreamWindow
	if err := proto.DecodeJSONPayload(frame, &msg); err != nil {
		return err
	}

	stream, ok := m.getStream(msg.StreamID)
	if !ok {
		return nil
	}

	stream.onWindowUpdate(msg.Delta)
	return nil
}

// handleHeartbeat handles a HEARTBEAT frame by responding with HEARTBEAT_ACK.
func (m *Mux) handleHeartbeat(frame *proto.Frame) error {
	// Receipt of a HEARTBEAT ping is itself a liveness signal from the
	// peer. In this protocol only the client sends pings, so without
	// recording them here the server's LastHeartbeat() never advances (it
	// never receives ACKs) and session cleanup kills healthy, idle
	// tunnels even while pings keep arriving.
	m.lastHeartbeat.Store(time.Now().UnixNano())

	ack := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameHeartbeatAck,
		StreamID: 0,
		Payload:  frame.Payload,
	}
	return m.frameWriter.Write(ack)
}

// handleHeartbeatAck handles a HEARTBEAT_ACK frame.
func (m *Mux) handleHeartbeatAck(frame *proto.Frame) error {
	m.lastHeartbeat.Store(time.Now().UnixNano())
	return nil
}

// LastHeartbeat returns the time of the last heartbeat frame received,
// whether a ping or an ack — either proves the peer connection is alive.
func (m *Mux) LastHeartbeat() time.Time {
	ns := m.lastHeartbeat.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// handleGoAway handles a GO_AWAY frame.
func (m *Mux) handleGoAway(frame *proto.Frame) error {
	return m.closeWithError(ErrMuxClosed)
}

// handleError handles an ERROR frame.
func (m *Mux) handleError(frame *proto.Frame) error {
	var msg proto.ErrorFrame
	if err := proto.DecodeJSONPayload(frame, &msg); err != nil {
		return err
	}
	return errors.New(msg.Message)
}

// sendDataFrame sends a STREAM_DATA frame.
func (m *Mux) sendDataFrame(streamID uint32, data []byte) error {
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamData,
		StreamID: streamID,
		Payload:  data,
	}
	return m.frameWriter.Write(frame)
}

// sendStreamClose sends a STREAM_CLOSE frame.
func (m *Mux) sendStreamClose(streamID uint32) error {
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamClose,
		StreamID: streamID,
		Payload:  nil,
	}
	return m.frameWriter.Write(frame)
}

// sendStreamReset sends a STREAM_RST frame.
func (m *Mux) sendStreamReset(streamID uint32) error {
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamRst,
		StreamID: streamID,
		Payload:  nil,
	}
	return m.frameWriter.Write(frame)
}

// sendWindowUpdate sends a STREAM_WINDOW frame.
func (m *Mux) sendWindowUpdate(streamID uint32, delta uint32) error {
	msg := &proto.StreamWindow{
		StreamID: streamID,
		Delta:    delta,
	}
	// EncodeJSONPayload cannot fail for StreamWindow (only uint32 fields)
	frame, _ := proto.EncodeJSONPayload(proto.FrameStreamWindow, streamID, msg)
	return m.frameWriter.Write(frame)
}

// getStream retrieves a stream by ID.
func (m *Mux) getStream(id uint32) (*Stream, bool) {
	if v, ok := m.streams.Load(id); ok {
		return v.(*Stream), true
	}
	return nil, false
}

// removeStream removes a stream from the mux.
func (m *Mux) removeStream(id uint32) {
	if _, loaded := m.streams.LoadAndDelete(id); loaded {
		m.streamCount.Add(-1)
	}
}

func (m *Mux) addStream(s *Stream) {
	m.streams.Store(s.id, s)
	m.streamCount.Add(1)
}
