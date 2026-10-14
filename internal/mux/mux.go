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
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		MaxStreams:        10000,
		WindowSize:        proto.DefaultWindowSize,
		MaxFrameSize:      64 * 1024, // 64 KB
		HeartbeatInterval: 30 * time.Second,
	}
}

// Mux is a stream multiplexer that carries multiple streams over a single connection.
type Mux struct {
	conn        net.Conn
	frameWriter *proto.FrameWriter
	frameReader *proto.FrameReader
	config      Config

	streams sync.Map // map[uint32]*Stream
	nextID  atomic.Uint32

	accept    chan *Stream      // incoming streams from remote
	controlCh chan *proto.Frame // control frames (auth, tunnel)
	done      chan struct{}
	err       atomic.Value // error that caused shutdown

	streamCount   atomic.Int32 // number of registered streams
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
	if config.MaxFrameSize <= 0 {
		config.MaxFrameSize = 64 * 1024
	}

	m := &Mux{
		conn:         conn,
		frameWriter:  proto.NewFrameWriter(conn),
		frameReader:  proto.NewFrameReader(conn),
		config:       config,
		accept:       make(chan *Stream, 128),
		controlCh:    make(chan *proto.Frame, 16),
		done:         make(chan struct{}),
		maxFrameSize: config.MaxFrameSize,
	}
	m.nextID.Store(2) // Start at 2 to avoid collision with ControlStreamID (0)

	return m
}

// OpenStream opens a new stream.
func (m *Mux) OpenStream() (*Stream, error) {
	select {
	case <-m.done:
		return nil, ErrMuxClosed
	default:
	}

	// Generate client stream ID (even numbers)
	if m.nextID.Load() > proto.MaxStreamID {
		return nil, ErrTooManyStreams // don't keep incrementing into a wrap
	}
	if int(m.streamCount.Load()) >= m.config.MaxStreams {
		return nil, ErrTooManyStreams
	}
	id := m.nextID.Add(2) - 2 // 2, 4, 6...
	if id > proto.MaxStreamID {
		return nil, ErrTooManyStreams
	}

	stream := newStream(id, m, m.config.WindowSize)
	m.addStream(stream)

	return stream, nil
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
			stream.onResetFrame()
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
	if frame.StreamID == proto.ControlStreamID || int(m.streamCount.Load()) >= m.config.MaxStreams {
		m.sendStreamReset(frame.StreamID)
		return nil
	}
	if _, exists := m.streams.Load(frame.StreamID); exists {
		m.sendStreamReset(frame.StreamID)
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
		stream.Reset()
	}

	return nil
}

// handleStreamData handles a STREAM_DATA frame.
func (m *Mux) handleStreamData(frame *proto.Frame) error {
	stream, ok := m.getStream(frame.StreamID)
	if !ok {
		// Stream not found, send reset
		m.sendStreamReset(frame.StreamID)
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
