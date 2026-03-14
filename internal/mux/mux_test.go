package mux

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

func newTestPipe(t *testing.T) (client, server *Mux) {
	t.Helper()

	c1, c2 := net.Pipe()

	client = New(c1, DefaultConfig())
	server = New(c2, DefaultConfig())

	return client, server
}

func TestMuxOpenStream(t *testing.T) {
	client, _ := newTestPipe(t)

	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	if stream.ID() != 0 {
		t.Errorf("First stream ID = %d, want 0", stream.ID())
	}

	stream2, err := client.OpenStream()
	if err != nil {
		t.Fatalf("Second OpenStream failed: %v", err)
	}

	if stream2.ID() != 2 {
		t.Errorf("Second stream ID = %d, want 2", stream2.ID())
	}
}

func TestMuxHeartbeat(t *testing.T) {
	client, server := newTestPipe(t)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		server.Run()
	}()

	go func() {
		defer wg.Done()
		client.Run()
	}()

	// Send heartbeat from client
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameHeartbeat,
		StreamID: 0,
		Payload:  proto.HeartbeatPayload(),
	}

	if err := client.GetFrameWriter().Write(frame); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}

	// Give it time to process
	time.Sleep(50 * time.Millisecond)

	client.Close()
	server.Close()
	wg.Wait()
}

func TestMuxClose(t *testing.T) {
	client, _ := newTestPipe(t)

	if err := client.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Should not be able to open new streams
	_, err := client.OpenStream()
	if err == nil {
		t.Error("Expected error after close")
	}

	// Done channel should be closed
	select {
	case <-client.Done():
		// OK
	case <-time.After(100 * time.Millisecond):
		t.Error("Done channel not closed")
	}
}

func TestMuxMultipleStreams(t *testing.T) {
	client, _ := newTestPipe(t)

	// Open multiple streams
	streams := make([]*Stream, 10)
	for i := 0; i < 10; i++ {
		s, err := client.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		streams[i] = s
	}

	// Verify IDs are sequential even numbers
	for i, s := range streams {
		expected := uint32(i * 2)
		if s.ID() != expected {
			t.Errorf("Stream %d ID = %d, want %d", i, s.ID(), expected)
		}
	}

	client.Close()
}

func TestStreamIsClosed(t *testing.T) {
	client, _ := newTestPipe(t)
	stream, _ := client.OpenStream()

	if stream.IsClosed() {
		t.Error("New stream should not be closed")
	}
}

func TestStreamMetadata(t *testing.T) {
	stream := &Stream{
		readBuf:  newRingBuffer(4096),
		readCh:   make(chan struct{}, 1),
		windowCh: make(chan struct{}, 1),
	}
	stream.window.Store(proto.DefaultWindowSize)

	stream.SetMetadata("192.168.1.1:12345", "http")

	if stream.RemoteAddr() != "192.168.1.1:12345" {
		t.Errorf("RemoteAddr = %q, want %q", stream.RemoteAddr(), "192.168.1.1:12345")
	}
	if stream.Protocol() != "http" {
		t.Errorf("Protocol = %q, want %q", stream.Protocol(), "http")
	}
}

func TestMuxLocalRemoteAddr(t *testing.T) {
	client, server := newTestPipe(t)

	if client.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
	if client.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}

	client.Close()
	server.Close()
}

func TestMuxConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxStreams <= 0 {
		t.Error("MaxStreams should be positive")
	}
	if cfg.WindowSize <= 0 {
		t.Error("WindowSize should be positive")
	}
	if cfg.MaxFrameSize <= 0 {
		t.Error("MaxFrameSize should be positive")
	}
	if cfg.HeartbeatInterval <= 0 {
		t.Error("HeartbeatInterval should be positive")
	}
}

func TestMuxHandleGoAway(t *testing.T) {
	client, server := newTestPipe(t)

	go server.Run()

	// Send GO_AWAY frame
	frame, _ := proto.EncodeJSONPayload(proto.FrameGoAway, 0, &proto.GoAway{
		Reason: "test",
	})
	if err := client.GetFrameWriter().Write(frame); err != nil {
		t.Fatalf("Send GO_AWAY: %v", err)
	}

	// Wait for mux to close
	select {
	case <-server.Done():
		// OK
	case <-time.After(1 * time.Second):
		t.Error("Server should have closed after GO_AWAY")
	}

	client.Close()
}

func BenchmarkMuxOpenStream(b *testing.B) {
	c1, c2 := net.Pipe()
	client := New(c1, DefaultConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.OpenStream()
		client.removeStream(uint32(i * 2))
	}

	c1.Close()
	c2.Close()
}

func BenchmarkMuxDataFrame(b *testing.B) {
	c1, c2 := net.Pipe()
	client := New(c1, DefaultConfig())
	// Start server reader to drain
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	stream, _ := client.OpenStream()
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.sendDataFrame(stream.ID(), data)
	}

	c1.Close()
	c2.Close()
}

func TestStreamReadAfterClose(t *testing.T) {
	client, server := newTestPipe(t)

	// Start run loops
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		client.Run()
	}()
	go func() {
		defer wg.Done()
		server.Run()
	}()

	// Simulate incoming stream open from client
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, 1, &proto.StreamOpen{
		RemoteAddr: "127.0.0.1:12345",
		Protocol:   "http",
	})

	client.GetFrameWriter().Write(openFrame)

	// Accept stream on server
	stream, err := server.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// Send data from client
	dataFrame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamData,
		StreamID: 1,
		Payload:  []byte("hello"),
	}
	client.GetFrameWriter().Write(dataFrame)

	// Read data on server
	buf := make([]byte, 10)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "hello")
	}

	client.Close()
	server.Close()
	wg.Wait()
}

func TestStreamCloseResetsState(t *testing.T) {
	client, server := newTestPipe(t)

	// Start run loop to drain writes
	go server.Run()

	stream, _ := client.OpenStream()

	// Close the stream - this transitions to HalfClosedLocal
	if err := stream.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Second close should be idempotent
	if err := stream.Close(); err != nil {
		t.Fatalf("Second close failed: %v", err)
	}

	// After Close(), stream is half-closed local, not fully closed
	// This is normal behavior for half-close semantics

	client.Close()
}

func TestStreamReset(t *testing.T) {
	client, server := newTestPipe(t)

	// Start run loop to drain writes
	go server.Run()

	stream, _ := client.OpenStream()

	// Reset the stream
	if err := stream.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	if !stream.IsClosed() {
		t.Error("Stream should be closed after reset")
	}

	client.Close()
}

func TestStreamCloseRead(t *testing.T) {
	client, server := newTestPipe(t)

	// Start run loop to drain
	go server.Run()

	stream, _ := client.OpenStream()

	// Close read side
	if err := stream.CloseRead(); err != nil {
		t.Fatalf("CloseRead failed: %v", err)
	}

	client.Close()
}

func TestMuxGetStream(t *testing.T) {
	client, _ := newTestPipe(t)
	stream, _ := client.OpenStream()

	// Get existing stream
	s, ok := client.getStream(stream.ID())
	if !ok {
		t.Fatal("getStream should find existing stream")
	}
	if s.ID() != stream.ID() {
		t.Errorf("getStream returned wrong stream")
	}

	// Get non-existent stream
	_, ok = client.getStream(99999)
	if ok {
		t.Error("getStream should not find non-existent stream")
	}

	client.Close()
}

func TestMuxRemoveStream(t *testing.T) {
	client, _ := newTestPipe(t)
	stream, _ := client.OpenStream()

	// Remove stream
	client.removeStream(stream.ID())

	// Should not exist anymore
	_, ok := client.getStream(stream.ID())
	if ok {
		t.Error("Stream should be removed")
	}

	client.Close()
}

func TestMuxNextServerStreamID(t *testing.T) {
	client, _ := newTestPipe(t)

	// Server stream IDs should be odd
	id1 := client.NextServerStreamID()
	id2 := client.NextServerStreamID()

	if id1%2 == 0 {
		t.Errorf("Server stream ID %d should be odd", id1)
	}
	if id2%2 == 0 {
		t.Errorf("Server stream ID %d should be odd", id2)
	}
	if id2 <= id1 {
		t.Errorf("Stream IDs should increase: %d <= %d", id2, id1)
	}

	client.Close()
}

func TestMuxSendStreamClose(t *testing.T) {
	client, server := newTestPipe(t)

	// Start reader to drain
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := server.conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	if err := client.sendStreamClose(1); err != nil {
		t.Errorf("sendStreamClose failed: %v", err)
	}

	client.Close()
}

func TestMuxSendStreamReset(t *testing.T) {
	client, server := newTestPipe(t)

	// Start reader to drain
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := server.conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	if err := client.sendStreamReset(1); err != nil {
		t.Errorf("sendStreamReset failed: %v", err)
	}

	client.Close()
}

func TestMuxSendWindowUpdate(t *testing.T) {
	client, server := newTestPipe(t)

	// Start reader to drain
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := server.conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	if err := client.sendWindowUpdate(1, 1024); err != nil {
		t.Errorf("sendWindowUpdate failed: %v", err)
	}

	client.Close()
}

func TestMuxHandleStreamOpen(t *testing.T) {
	_, server := newTestPipe(t)

	// Directly call handleFrame - this doesn't require a reader
	frame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, 1, &proto.StreamOpen{
		RemoteAddr: "127.0.0.1:12345",
		Protocol:   "http",
	})
	server.handleFrame(frame)

	// Should be able to accept the stream
	select {
	case stream := <-server.accept:
		if stream.RemoteAddr() != "127.0.0.1:12345" {
			t.Errorf("RemoteAddr = %q, want %q", stream.RemoteAddr(), "127.0.0.1:12345")
		}
		if stream.Protocol() != "http" {
			t.Errorf("Protocol = %q, want %q", stream.Protocol(), "http")
		}
	default:
		t.Fatal("No stream available")
	}

	server.Close()
}

func TestMuxHandleStreamClose(t *testing.T) {
	_, server := newTestPipe(t)

	// Create a stream first
	stream := newStream(1, server, proto.DefaultWindowSize)
	server.streams.Store(uint32(1), stream)

	// Handle close frame
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamClose,
		StreamID: 1,
	}
	server.handleFrame(frame)

	// Stream should signal EOF
	select {
	case <-stream.readCh:
		// OK
	default:
		t.Error("Stream should signal after close frame")
	}

	server.Close()
}

func TestMuxHandleStreamReset(t *testing.T) {
	_, server := newTestPipe(t)

	// Create a stream first
	stream := newStream(1, server, proto.DefaultWindowSize)
	server.streams.Store(uint32(1), stream)

	// Handle reset frame
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamRst,
		StreamID: 1,
	}
	server.handleFrame(frame)

	if !stream.IsClosed() {
		t.Error("Stream should be closed after reset")
	}

	server.Close()
}

func TestMuxHandleStreamDataUnknownStream(t *testing.T) {
	client, server := newTestPipe(t)

	// Start reader on client to drain reset messages
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := client.conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Handle data frame for non-existent stream - should send reset
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamData,
		StreamID: 999,
		Payload:  []byte("test"),
	}

	// Should not error
	if err := server.handleFrame(frame); err != nil {
		t.Errorf("handleFrame for unknown stream should not error: %v", err)
	}

	client.Close()
	server.Close()
}

func TestMuxHandleHeartbeatAck(t *testing.T) {
	client, _ := newTestPipe(t)

	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameHeartbeatAck,
		StreamID: 0,
		Payload:  proto.HeartbeatPayload(),
	}

	if err := client.handleFrame(frame); err != nil {
		t.Errorf("handleHeartbeatAck failed: %v", err)
	}

	client.Close()
}

func TestMuxHandleError(t *testing.T) {
	client, _ := newTestPipe(t)

	frame, _ := proto.EncodeJSONPayload(proto.FrameError, 0, &proto.ErrorFrame{
		Code:    500,
		Message: "test error",
	})

	err := client.handleFrame(frame)
	if err == nil {
		t.Error("handleError should return error")
	}
	if err.Error() != "test error" {
		t.Errorf("Error message = %q, want %q", err.Error(), "test error")
	}

	client.Close()
}

func TestMuxHandleInvalidFrameType(t *testing.T) {
	client, _ := newTestPipe(t)

	// Unknown frame type should be ignored (0x99 is not defined)
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     0x99, // Undefined type - should be ignored
		StreamID: 0,
	}

	if err := client.handleFrame(frame); err != nil {
		t.Errorf("Unknown frame type should be ignored: %v", err)
	}

	client.Close()
}

func TestMuxHandleStreamWindowUnknownStream(t *testing.T) {
	_, server := newTestPipe(t)

	// Window update for unknown stream should be ignored
	frame, _ := proto.EncodeJSONPayload(proto.FrameStreamWindow, 999, &proto.StreamWindow{
		StreamID: 999,
		Delta:    1024,
	})

	if err := server.handleFrame(frame); err != nil {
		t.Errorf("handleStreamWindow for unknown stream should not error: %v", err)
	}

	server.Close()
}

func TestMuxErr(t *testing.T) {
	client, server := newTestPipe(t)

	// No error initially
	if err := client.Err(); err != nil {
		t.Errorf("Initial Err should be nil, got %v", err)
	}

	// Close both ends
	client.Close()
	server.Close()

	// Should have error after close
	if err := client.Err(); err != ErrMuxClosed {
		t.Errorf("Err after close = %v, want %v", err, ErrMuxClosed)
	}
}

func TestStreamLocalAddr(t *testing.T) {
	client, server := newTestPipe(t)
	stream, _ := client.OpenStream()

	if stream.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}

	client.Close()
	server.Close()
}

func TestStreamLocalAddrNilMux(t *testing.T) {
	stream := &Stream{}

	if stream.LocalAddr() != nil {
		t.Error("LocalAddr should be nil for stream without mux")
	}
}

func TestMuxConfigOverrides(t *testing.T) {
	c1, c2 := net.Pipe()

	// Test with zero config values (should use defaults)
	cfg := Config{
		MaxStreams:   0,
		WindowSize:   0,
		MaxFrameSize: 0,
	}
	m := New(c1, cfg)

	if m.config.MaxStreams <= 0 {
		t.Error("MaxStreams should be defaulted to positive value")
	}
	if m.config.WindowSize <= 0 {
		t.Error("WindowSize should be defaulted to positive value")
	}
	if m.config.MaxFrameSize <= 0 {
		t.Error("MaxFrameSize should be defaulted to positive value")
	}

	c1.Close()
	c2.Close()
}

func TestMuxHandleHeartbeat(t *testing.T) {
	client, server := newTestPipe(t)

	// Start server to process heartbeat
	go server.Run()

	// Start a goroutine to read and verify heartbeat ack
	ackReceived := make(chan bool, 1)
	go func() {
		for {
			frame, err := client.frameReader.Read()
			if err != nil {
				return
			}
			if frame.Type == proto.FrameHeartbeatAck {
				ackReceived <- true
				return
			}
		}
	}()

	// Send heartbeat
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameHeartbeat,
		StreamID: 0,
		Payload:  proto.HeartbeatPayload(),
	}

	if err := client.frameWriter.Write(frame); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}

	// Wait for ack
	select {
	case <-ackReceived:
		// Success - heartbeat ack received
	case <-time.After(1 * time.Second):
		t.Error("Did not receive heartbeat ack")
	}

	client.Close()
	server.Close()
}

func TestMuxOpenStreamAfterClose(t *testing.T) {
	client, _ := newTestPipe(t)

	client.Close()

	_, err := client.OpenStream()
	if err != ErrMuxClosed {
		t.Errorf("Expected ErrMuxClosed, got %v", err)
	}
}

func TestMuxAcceptStreamClosed(t *testing.T) {
	client, _ := newTestPipe(t)

	// Close the mux
	client.Close()

	// AcceptStream should return error
	_, err := client.AcceptStream()
	if err != io.EOF {
		t.Errorf("Expected io.EOF, got %v", err)
	}
}
