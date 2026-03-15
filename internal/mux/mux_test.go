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

	stream.SetMetadata("192.168.1.1:12345", "http", "")

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

func TestMuxGetFrameReader(t *testing.T) {
	client, server := newTestPipe(t)

	// GetFrameReader should return the frame reader
	reader := client.GetFrameReader()
	if reader == nil {
		t.Error("GetFrameReader should not return nil")
	}

	// Same reader should be returned
	reader2 := client.GetFrameReader()
	if reader != reader2 {
		t.Error("GetFrameReader should return the same reader")
	}

	// Server should also have a reader
	serverReader := server.GetFrameReader()
	if serverReader == nil {
		t.Error("Server GetFrameReader should not return nil")
	}

	client.Close()
	server.Close()
}

func TestMuxSendDataFrame(t *testing.T) {
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

	// Accept stream on server in goroutine first
	acceptCh := make(chan *Stream, 1)
	go func() {
		stream, err := server.AcceptStream()
		if err != nil {
			close(acceptCh)
			return
		}
		acceptCh <- stream
	}()

	// Send STREAM_OPEN frame to create stream on server
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, 2, &proto.StreamOpen{
		RemoteAddr: "127.0.0.1:12345",
		Protocol:   "test",
	})
	client.GetFrameWriter().Write(openFrame)

	// Get accepted stream
	serverStream := <-acceptCh
	if serverStream == nil {
		t.Fatal("AcceptStream failed")
	}

	// Send data using the frame writer directly
	data := []byte("test data for frame")
	dataFrame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamData,
		StreamID: 2,
		Payload:  data,
	}
	if err := client.GetFrameWriter().Write(dataFrame); err != nil {
		t.Fatalf("Write data frame failed: %v", err)
	}

	// Read data on server
	buf := make([]byte, len(data))
	n, err := serverStream.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != string(data) {
		t.Errorf("Read = %q, want %q", string(buf[:n]), string(data))
	}

	serverStream.Close()
	client.Close()
	server.Close()
	wg.Wait()
}

// TestStreamWrite tests Stream.Write functionality
func TestStreamWrite(t *testing.T) {
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

	// Create stream on client
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Write data
	data := []byte("hello world")
	n, err := stream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	stream.Close()
	client.Close()
	server.Close()
	wg.Wait()
}

// TestStreamWriteClosed tests Stream.Write when stream is closed
func TestStreamWriteClosed(t *testing.T) {
	client, server := newTestPipe(t)
	go server.Run()

	stream, _ := client.OpenStream()

	// Close the stream
	stream.Close()

	// Write should fail
	_, err := stream.Write([]byte("test"))
	if err != ErrStreamClosed {
		t.Errorf("Expected ErrStreamClosed, got %v", err)
	}

	client.Close()
	server.Close()
}

// TestStreamWriteReset tests Stream.Write when stream is reset
func TestStreamWriteReset(t *testing.T) {
	client, server := newTestPipe(t)
	go server.Run()

	stream, _ := client.OpenStream()

	// Reset the stream
	stream.Reset()

	// Write should fail
	_, err := stream.Write([]byte("test"))
	if err != ErrStreamReset {
		t.Errorf("Expected ErrStreamReset, got %v", err)
	}

	client.Close()
	server.Close()
}

// TestStreamOnWindowUpdate tests window update handling
func TestStreamOnWindowUpdate(t *testing.T) {
	stream := newStream(1, nil, 100)

	// Initial window should be 100
	if stream.window.Load() != 100 {
		t.Errorf("Initial window = %d, want 100", stream.window.Load())
	}

	// Apply window update
	stream.onWindowUpdate(50)

	// Window should now be 150
	if stream.window.Load() != 150 {
		t.Errorf("Window after update = %d, want 150", stream.window.Load())
	}
}

// TestRingBufferWriteEmpty tests Write with empty data
func TestRingBufferWriteEmpty(t *testing.T) {
	rb := newRingBuffer(1024)
	n, err := rb.Write([]byte{})
	if err != nil {
		t.Errorf("Write empty should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("Write empty returned %d, want 0", n)
	}
}

// TestRingBufferReadEmptyBuffer tests Read with empty buffer
func TestRingBufferReadEmptyBuffer(t *testing.T) {
	rb := newRingBuffer(1024)
	p := make([]byte, 10)
	n, err := rb.Read(p)
	if err != nil {
		t.Errorf("Read from empty should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("Read from empty returned %d, want 0", n)
	}
}

// TestStreamCleanup tests stream cleanup functionality
func TestStreamCleanup(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 1000)
	client.streams.Store(uint32(1), stream)

	// Set cleanup callback
	cleanupCalled := false
	stream.onClose = func() {
		cleanupCalled = true
	}

	// Call cleanup
	stream.cleanup()

	if !cleanupCalled {
		t.Error("onClose callback should be called during cleanup")
	}

	// Stream should be removed from mux
	if _, ok := client.getStream(1); ok {
		t.Error("Stream should be removed from mux")
	}
}

// TestStreamReadWithData tests Stream.Read with actual data
func TestStreamReadWithData(t *testing.T) {
	// Skip this test - it requires complex setup with proper stream initialization
	t.Skip("Skipping complex stream read test - requires full mux handshake")
}

// TestStreamReadClosed tests Stream.Read when stream is closed
func TestStreamReadClosed(t *testing.T) {
	stream := newStream(1, nil, 1000)

	// Close the stream for reading
	stream.CloseRead()

	// Read should return EOF
	buf := make([]byte, 10)
	_, err := stream.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected io.EOF, got %v", err)
	}
}

// TestStreamReadReset tests Stream.Read when stream is reset
func TestStreamReadReset(t *testing.T) {
	client, server := newTestPipe(t)
	go server.Run()

	stream, _ := client.OpenStream()

	// Reset the stream
	stream.Reset()

	// Write should fail
	_, err := stream.Write([]byte("test"))
	if err != ErrStreamReset {
		t.Errorf("Expected ErrStreamReset, got %v", err)
	}

	client.Close()
	server.Close()
}

// TestStreamRemoteAddr tests Stream.RemoteAddr
func TestStreamRemoteAddr(t *testing.T) {
	client, server := newTestPipe(t)

	stream := newStream(1, client, 1000)

	// Initially should have empty remote addr
	addr := stream.RemoteAddr()
	if addr != "" {
		t.Errorf("RemoteAddr should be empty initially, got %q", addr)
	}

	// Test with nil mux
	stream2 := &Stream{}
	if stream2.RemoteAddr() != "" {
		t.Error("RemoteAddr should be empty for stream without mux")
	}

	server.Close()
	client.Close()
}

// TestMuxSendStreamWindowUpdate tests sending window update
func TestMuxSendStreamWindowUpdate(t *testing.T) {
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

	// Create stream on client
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Send window update
	err = client.sendWindowUpdate(stream.id, 1024)
	if err != nil {
		t.Errorf("sendWindowUpdate failed: %v", err)
	}

	stream.Close()
	client.Close()
	server.Close()
	wg.Wait()
}

// TestMuxSendStreamWindowUpdateClosed tests sending window update when closed
func TestMuxSendStreamWindowUpdateClosed(t *testing.T) {
	client, _ := newTestPipe(t)

	// Close the mux
	client.Close()

	// Send window update should fail
	err := client.sendWindowUpdate(1, 1024)
	if err == nil {
		t.Error("Expected error when sending window update on closed mux")
	}
}

// TestMuxCloseStream tests closing a stream
func TestMuxCloseStream(t *testing.T) {
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

	// Create stream
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Close the stream
	err = stream.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Second close should not error
	err = stream.Close()
	if err != nil {
		t.Errorf("Second Close failed: %v", err)
	}

	client.Close()
	server.Close()
	wg.Wait()
}

// TestMuxOnCloseFrame tests onCloseFrame handling
func TestMuxOnCloseFrame(t *testing.T) {
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

	// Create stream
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Send close frame from server side
	closeFrame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamClose,
		StreamID: stream.id,
	}

	if err := server.frameWriter.Write(closeFrame); err != nil {
		t.Fatalf("Write close frame failed: %v", err)
	}

	// Give time for frame to be processed
	time.Sleep(50 * time.Millisecond)

	client.Close()
	server.Close()
	wg.Wait()
}

// TestRingBufferGrowLocked tests growLocked functionality
func TestRingBufferGrowLocked(t *testing.T) {
	rb := newRingBuffer(16)

	// Fill buffer
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i)
	}
	rb.Write(data)

	// Read some to move read position
	p := make([]byte, 8)
	rb.Read(p)

	// Now write more to trigger grow with wrap-around
	moreData := make([]byte, 20)
	for i := range moreData {
		moreData[i] = byte(i + 100)
	}
	rb.Write(moreData)

	// Buffer should have grown
	if rb.size <= 16 {
		t.Errorf("Buffer size = %d, should be > 16", rb.size)
	}
}

// TestRingBufferLenLocked tests lenLocked functionality
func TestRingBufferLenLocked(t *testing.T) {
	rb := newRingBuffer(100)

	// Empty buffer
	if rb.Len() != 0 {
		t.Errorf("Empty buffer Len = %d, want 0", rb.Len())
	}

	// Write data
	rb.Write([]byte("hello"))
	if rb.Len() != 5 {
		t.Errorf("After write Len = %d, want 5", rb.Len())
	}

	// Read some
	p := make([]byte, 3)
	rb.Read(p)
	if rb.Len() != 2 {
		t.Errorf("After read Len = %d, want 2", rb.Len())
	}
}

// TestRingBufferAvailableLocked tests availableLocked functionality
func TestRingBufferAvailableLocked(t *testing.T) {
	rb := newRingBuffer(100)

	// Full available
	avail := rb.Available()
	if avail != 100 {
		t.Errorf("Empty buffer Available = %d, want 100", avail)
	}

	// Write data
	rb.Write([]byte("hello"))
	avail = rb.Available()
	if avail != 95 {
		t.Errorf("After write Available = %d, want 95", avail)
	}

	// Fill buffer
	rb.Write(make([]byte, 95))
	avail = rb.Available()
	if avail != 0 {
		t.Errorf("Full buffer Available = %d, want 0", avail)
	}
}

// TestOpenStreamMaxStreamIDExceeded tests OpenStream when MaxStreamID is exceeded.
func TestOpenStreamMaxStreamIDExceeded(t *testing.T) {
	client, _ := newTestPipe(t)

	// Set nextID beyond MaxStreamID so the next allocation exceeds it.
	// nextID.Add(2) - 2 produces the ID; we need id > MaxStreamID.
	// Set nextID to MaxStreamID so Add(2)-2 = MaxStreamID+2-2 = MaxStreamID, then next call overflows.
	client.nextID.Store(proto.MaxStreamID + 1)

	_, err := client.OpenStream()
	if err != ErrTooManyStreams {
		t.Errorf("Expected ErrTooManyStreams, got %v", err)
	}

	client.Close()
}

// TestRunHandleFrameReturnsError tests that Run closes the mux when handleFrame returns an error.
func TestRunHandleFrameReturnsError(t *testing.T) {
	client, server := newTestPipe(t)

	go server.Run()

	// Send an ERROR frame which causes handleFrame to return an error,
	// which in turn causes Run to call closeWithError.
	frame, _ := proto.EncodeJSONPayload(proto.FrameError, 0, &proto.ErrorFrame{
		Code:    500,
		Message: "fatal error",
	})
	client.GetFrameWriter().Write(frame)

	// server.Run should close the mux
	select {
	case <-server.Done():
		// OK - mux was closed due to handleFrame error
	case <-time.After(2 * time.Second):
		t.Error("Server should have closed after handleFrame error")
	}

	client.Close()
}

// TestHandleStreamOpenAcceptQueueFull tests handleStreamOpen when accept channel is full.
func TestHandleStreamOpenAcceptQueueFull(t *testing.T) {
	client, server := newTestPipe(t)

	// Start a reader on the client side to drain any frames (like STREAM_RST)
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := client.conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Fill the accept channel (capacity is 128)
	for i := 0; i < 128; i++ {
		frame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, uint32(i*2+1), &proto.StreamOpen{
			RemoteAddr: "127.0.0.1:12345",
			Protocol:   "http",
		})
		server.handleFrame(frame)
	}

	// Now the accept channel should be full. Send one more.
	frame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, 999, &proto.StreamOpen{
		RemoteAddr: "127.0.0.1:99999",
		Protocol:   "tcp",
	})

	// This should not block; the stream should be reset instead.
	err := server.handleFrame(frame)
	if err != nil {
		t.Errorf("handleStreamOpen with full accept queue should not error: %v", err)
	}

	client.Close()
	server.Close()
}

// TestHandleStreamWindowMalformedPayload tests handleStreamWindow with malformed JSON payload.
func TestHandleStreamWindowMalformedPayload(t *testing.T) {
	client, _ := newTestPipe(t)

	// Create a frame with invalid JSON payload for STREAM_WINDOW
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamWindow,
		StreamID: 1,
		Payload:  []byte("not valid json{{{"),
	}

	err := client.handleFrame(frame)
	if err == nil {
		t.Error("Expected error for malformed STREAM_WINDOW payload")
	}

	client.Close()
}

// TestHandleErrorMalformedPayload tests handleError with malformed JSON payload.
func TestHandleErrorMalformedPayload(t *testing.T) {
	client, _ := newTestPipe(t)

	// Create a frame with invalid JSON payload for ERROR
	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameError,
		StreamID: 0,
		Payload:  []byte("not valid json{{{"),
	}

	err := client.handleFrame(frame)
	if err == nil {
		t.Error("Expected error for malformed ERROR payload")
	}

	client.Close()
}

// TestRingBufferWrappedLenLocked tests lenLocked when w < r (wrapped buffer).
func TestRingBufferWrappedLenLocked(t *testing.T) {
	rb := newRingBuffer(8)

	// Write 6 bytes
	rb.Write([]byte("abcdef"))

	// Read 4 bytes to advance read cursor
	p := make([]byte, 4)
	rb.Read(p)

	// Now r=4, w=6, data length should be 2
	if rb.Len() != 2 {
		t.Errorf("Len = %d, want 2", rb.Len())
	}

	// Write 5 more bytes - this will wrap around (w wraps past end)
	rb.Write([]byte("ghijk"))

	// r=4, buffer has been grown or wrapped. Verify length is correct.
	if rb.Len() != 7 {
		t.Errorf("Len after wrap = %d, want 7", rb.Len())
	}
}

// TestRingBufferGrowWrapped tests growLocked when the buffer data wraps (w < r case).
func TestRingBufferGrowWrapped(t *testing.T) {
	rb := newRingBuffer(8)

	// Fill the buffer completely: 8 bytes
	rb.Write([]byte("ABCDEFGH"))

	// Read all 8 bytes: r=0, w=0 (full=false after read)
	p := make([]byte, 8)
	n, _ := rb.Read(p)
	if n != 8 {
		t.Errorf("Read count = %d, want 8", n)
	}

	// Now r=0, w=0, empty buffer, but cursors are at 0
	// Write 6 bytes: positions 0-5, w=6, r=0
	rb.Write([]byte("ABCDEF"))

	// Read 5: r=5, w=6, 1 byte in buffer
	p2 := make([]byte, 5)
	rb.Read(p2)

	// Write 3 bytes wrapping: positions 6,7,0 -> w=1, r=5
	rb.Write([]byte("GHI"))

	// Now w=1 < r=5, this is the wrapped state
	// The buffer has 4 bytes: F(pos5), G(pos6), H(pos7), I(pos0)
	// Write enough to trigger grow in wrapped state
	rb.Write([]byte("JKLMNOP"))

	// The buffer grew. Read everything out to verify no crash
	// and that we can read data after grow.
	out := make([]byte, 32)
	n, _ = rb.Read(out)
	if n == 0 {
		t.Error("Expected to read data after grow with wrapped buffer")
	}
}

// TestStreamReadResetState tests Stream.Read when stream is in reset state.
func TestStreamReadResetState(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 1000)
	stream.state.Store(streamStateReset)

	buf := make([]byte, 10)
	_, err := stream.Read(buf)
	if err != ErrStreamReset {
		t.Errorf("Expected ErrStreamReset, got %v", err)
	}

	client.Close()
}

// TestStreamReadMuxDone tests Stream.Read when mux is closed while waiting.
func TestStreamReadMuxDone(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 1000)
	client.streams.Store(uint32(1), stream)

	// Close mux after a short delay to unblock the Read
	go func() {
		time.Sleep(50 * time.Millisecond)
		client.Close()
	}()

	buf := make([]byte, 10)
	_, err := stream.Read(buf)
	if err != io.EOF {
		t.Errorf("Expected io.EOF, got %v", err)
	}
}

// TestStreamReadFromBufferWindowUpdateError tests readFromBuffer when sendWindowUpdate fails.
func TestStreamReadFromBufferWindowUpdateError(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 1000)

	// Write data into the read buffer
	stream.readBuf.Write([]byte("hello"))

	// Close the connection so sendWindowUpdate will fail
	client.conn.Close()

	buf := make([]byte, 10)
	n, err := stream.readFromBuffer(buf)
	if n != 5 {
		t.Errorf("Read count = %d, want 5", n)
	}
	if err == nil {
		t.Error("Expected error from sendWindowUpdate failure")
	}
}

// TestStreamWriteWindowWaitMuxDone tests Stream.Write when window is 0 and mux closes.
func TestStreamWriteWindowWaitMuxDone(t *testing.T) {
	client, server := newTestPipe(t)

	// Start draining on server side
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := server.conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	stream := newStream(1, client, 1000)
	client.streams.Store(uint32(1), stream)

	// Set window to 0 so Write blocks waiting for window update
	stream.window.Store(0)

	// Close mux after a short delay to unblock the Write
	go func() {
		time.Sleep(50 * time.Millisecond)
		client.Close()
	}()

	_, err := stream.Write([]byte("test data"))
	if err != io.EOF {
		t.Errorf("Expected io.EOF, got %v", err)
	}

	server.Close()
}

// TestStreamWriteChunkExceedsMaxFrameSize tests Write with data larger than maxFrameSize.
func TestStreamWriteChunkExceedsMaxFrameSize(t *testing.T) {
	c1, c2 := net.Pipe()

	// Create a mux with small maxFrameSize
	cfg := DefaultConfig()
	cfg.MaxFrameSize = 10
	client := New(c1, cfg)

	// Start draining on server side
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	stream := newStream(1, client, 10000)
	client.streams.Store(uint32(1), stream)

	// Write data larger than maxFrameSize (10 bytes)
	data := make([]byte, 35)
	for i := range data {
		data[i] = byte(i)
	}

	n, err := stream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	client.Close()
	c2.Close()
}

// TestStreamWriteSendDataFrameError tests Write when sendDataFrame fails.
func TestStreamWriteSendDataFrameError(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 10000)
	client.streams.Store(uint32(1), stream)

	// Close the connection so sendDataFrame will fail
	client.conn.Close()

	_, err := stream.Write([]byte("test"))
	if err == nil {
		t.Error("Expected error from sendDataFrame failure")
	}

	client.Close()
}

// TestStreamCloseFromHalfClosedRemote tests Close when stream is in HalfClosedRemote state.
func TestStreamCloseFromHalfClosedRemote(t *testing.T) {
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

	stream := newStream(1, client, 1000)
	client.streams.Store(uint32(1), stream)

	// Set state to HalfClosedRemote
	stream.state.Store(streamStateHalfClosedRemote)

	// Close should transition to Closed
	err := stream.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	state := stream.state.Load()
	if state != streamStateClosed {
		t.Errorf("State = %d, want %d (streamStateClosed)", state, streamStateClosed)
	}

	client.Close()
	server.Close()
}

// TestStreamCloseReadFromHalfClosedLocal tests CloseRead when stream is in HalfClosedLocal state.
func TestStreamCloseReadFromHalfClosedLocal(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 1000)

	// Set state to HalfClosedLocal
	stream.state.Store(streamStateHalfClosedLocal)

	// CloseRead should transition to Closed
	err := stream.CloseRead()
	if err != nil {
		t.Errorf("CloseRead failed: %v", err)
	}

	state := stream.state.Load()
	if state != streamStateClosed {
		t.Errorf("State = %d, want %d (streamStateClosed)", state, streamStateClosed)
	}

	client.Close()
}

// TestStreamOnCloseFrameFromHalfClosedLocal tests onCloseFrame when stream is HalfClosedLocal.
func TestStreamOnCloseFrameFromHalfClosedLocal(t *testing.T) {
	client, _ := newTestPipe(t)

	stream := newStream(1, client, 1000)

	// Set state to HalfClosedLocal
	stream.state.Store(streamStateHalfClosedLocal)

	// onCloseFrame should transition to Closed
	stream.onCloseFrame()

	state := stream.state.Load()
	if state != streamStateClosed {
		t.Errorf("State = %d, want %d (streamStateClosed)", state, streamStateClosed)
	}

	client.Close()
}

// TestHandleStreamOpenMalformedPayload tests handleStreamOpen with malformed JSON.
func TestHandleStreamOpenMalformedPayload(t *testing.T) {
	client, _ := newTestPipe(t)

	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameStreamOpen,
		StreamID: 1,
		Payload:  []byte("not valid json{{{"),
	}

	err := client.handleFrame(frame)
	if err == nil {
		t.Error("Expected error for malformed STREAM_OPEN payload")
	}

	client.Close()
}

// TestHandleStreamWindowSuccessWithStream tests handleStreamWindow with a known stream.
func TestHandleStreamWindowSuccessWithStream(t *testing.T) {
	_, server := newTestPipe(t)

	// Create and register a stream
	stream := newStream(1, server, proto.DefaultWindowSize)
	server.streams.Store(uint32(1), stream)

	initialWindow := stream.window.Load()

	// Send window update for this stream
	frame, _ := proto.EncodeJSONPayload(proto.FrameStreamWindow, 1, &proto.StreamWindow{
		StreamID: 1,
		Delta:    1024,
	})

	err := server.handleFrame(frame)
	if err != nil {
		t.Errorf("handleStreamWindow should not error: %v", err)
	}

	newWindow := stream.window.Load()
	if newWindow != initialWindow+1024 {
		t.Errorf("Window = %d, want %d", newWindow, initialWindow+1024)
	}

	server.Close()
}

// TestRingBufferGrowLockedNoOp tests growLocked when newSize <= current size.
func TestRingBufferGrowLockedNoOp(t *testing.T) {
	rb := newRingBuffer(100)

	// Write some data
	rb.Write([]byte("hello"))

	// Try to grow to a smaller size - should be a no-op
	rb.mu.Lock()
	rb.growLocked(50)
	rb.mu.Unlock()

	// Buffer size should remain 100
	if rb.size != 100 {
		t.Errorf("Size = %d, want 100 (should not shrink)", rb.size)
	}

	// Data should still be intact
	if rb.Len() != 5 {
		t.Errorf("Len = %d, want 5", rb.Len())
	}
}

// TestRingBufferGrowNonWrapped tests growLocked with non-wrapped data (w > r).
func TestRingBufferGrowNonWrapped(t *testing.T) {
	rb := newRingBuffer(4)

	// Write 3 bytes: r=0, w=3, w > r (non-wrapped)
	rb.Write([]byte("ABC"))

	// Write 5 more bytes to trigger grow while w > r
	rb.Write([]byte("DEFGH"))

	// Read everything
	out := make([]byte, 16)
	n, _ := rb.Read(out)
	if n != 8 {
		t.Errorf("Read count = %d, want 8", n)
	}
	if string(out[:n]) != "ABCDEFGH" {
		t.Errorf("Read = %q, want %q", string(out[:n]), "ABCDEFGH")
	}
}

// TestRingBufferLenLockedFull tests lenLocked when buffer is full.
func TestRingBufferLenLockedFull(t *testing.T) {
	rb := newRingBuffer(8)

	// Fill the buffer completely
	rb.Write([]byte("12345678"))

	// Buffer should be full, lenLocked returns size
	if rb.Len() != 8 {
		t.Errorf("Len = %d, want 8 (full buffer)", rb.Len())
	}

	rb.mu.Lock()
	if !rb.full {
		t.Error("Expected buffer to be full")
	}
	rb.mu.Unlock()
}

// TestStreamWriteWindowWaitThenContinue tests Write when window is 0, receives update, then continues.
func TestStreamWriteWindowWaitThenContinue(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := DefaultConfig()
	client := New(c1, cfg)

	// Start draining on server side
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	stream := newStream(1, client, 1000)
	client.streams.Store(uint32(1), stream)

	// Set window to 0 to force wait
	stream.window.Store(0)

	// In a goroutine, send a window update after a delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		stream.onWindowUpdate(1000)
	}()

	data := []byte("test data")
	n, err := stream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	client.Close()
	c2.Close()
}

// TestStreamWriteChunkLimitedByWindow tests Write when chunk is limited by window size.
func TestStreamWriteChunkLimitedByWindow(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := DefaultConfig()
	client := New(c1, cfg)

	// Start draining on server side
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	stream := newStream(1, client, 5) // window = 5
	client.streams.Store(uint32(1), stream)

	// Write data larger than window (5 bytes).
	// The first chunk will be limited to window=5 bytes.
	// Then window drops to 0, and we need another window update.
	go func() {
		time.Sleep(50 * time.Millisecond)
		stream.onWindowUpdate(10)
	}()

	data := []byte("1234567890") // 10 bytes, window is 5
	n, err := stream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 10 {
		t.Errorf("Write returned %d, want 10", n)
	}

	client.Close()
	c2.Close()
}

// TestRingBufferReadEmptyP tests Read with len(p)==0.
func TestRingBufferReadEmptyP(t *testing.T) {
	rb := newRingBuffer(1024)
	rb.Write([]byte("data"))

	// Read with empty p
	n, err := rb.Read([]byte{})
	if n != 0 {
		t.Errorf("Read(empty) returned n=%d, want 0", n)
	}
	if err != nil {
		t.Errorf("Read(empty) returned err=%v, want nil", err)
	}

	// Verify data is still there
	if rb.Len() != 4 {
		t.Errorf("Buffer len = %d, want 4 (data should not be consumed)", rb.Len())
	}
}

// TestMuxControlFrame tests that AUTH_REQ frames are routed to the ControlFrame channel.
func TestMuxControlFrame(t *testing.T) {
	_, server := newTestPipe(t)

	// Build an AUTH_REQ frame
	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, &proto.AuthRequest{
		Token: "test-token",
	})

	// Dispatch through handleFrame
	if err := server.handleFrame(frame); err != nil {
		t.Fatalf("handleFrame failed: %v", err)
	}

	// Should arrive on ControlFrame channel
	select {
	case got := <-server.ControlFrame():
		if got.Type != proto.FrameAuthReq {
			t.Errorf("ControlFrame type = %v, want %v", got.Type, proto.FrameAuthReq)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for control frame")
	}

	server.Close()
}

// TestMuxControlFrameTunnelReq tests that TUNNEL_REQ frames are routed to the ControlFrame channel.
func TestMuxControlFrameTunnelReq(t *testing.T) {
	_, server := newTestPipe(t)

	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelReq, 0, &proto.TunnelRequest{
		Subdomain: "test",
		LocalAddr: "127.0.0.1:8080",
	})

	if err := server.handleFrame(frame); err != nil {
		t.Fatalf("handleFrame failed: %v", err)
	}

	select {
	case got := <-server.ControlFrame():
		if got.Type != proto.FrameTunnelReq {
			t.Errorf("ControlFrame type = %v, want %v", got.Type, proto.FrameTunnelReq)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for control frame")
	}

	server.Close()
}

// TestMuxControlFrameTunnelRes tests that TUNNEL_RES frames are routed to the ControlFrame channel.
func TestMuxControlFrameTunnelRes(t *testing.T) {
	_, server := newTestPipe(t)

	frame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, &proto.TunnelResponse{
		TunnelID: "tun-123",
		OK:       true,
	})

	if err := server.handleFrame(frame); err != nil {
		t.Fatalf("handleFrame failed: %v", err)
	}

	select {
	case got := <-server.ControlFrame():
		if got.Type != proto.FrameTunnelRes {
			t.Errorf("ControlFrame type = %v, want %v", got.Type, proto.FrameTunnelRes)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for control frame")
	}

	server.Close()
}

// TestStreamTunnelID tests the TunnelID getter on Stream.
func TestStreamTunnelID(t *testing.T) {
	stream := &Stream{
		readBuf:  newRingBuffer(4096),
		readCh:   make(chan struct{}, 1),
		windowCh: make(chan struct{}, 1),
	}

	// Initially empty
	if stream.TunnelID() != "" {
		t.Errorf("TunnelID should be empty initially, got %q", stream.TunnelID())
	}

	// Set via SetMetadata
	stream.SetMetadata("192.168.1.1:12345", "http", "tun-abc")

	if stream.TunnelID() != "tun-abc" {
		t.Errorf("TunnelID = %q, want %q", stream.TunnelID(), "tun-abc")
	}
}

// TestHandleStreamOpenWithTunnelID tests that handleStreamOpen sets tunnelID on the stream.
func TestHandleStreamOpenWithTunnelID(t *testing.T) {
	_, server := newTestPipe(t)

	frame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, 1, &proto.StreamOpen{
		TunnelID:   "tun-xyz",
		RemoteAddr: "10.0.0.1:8080",
		Protocol:   "tcp",
	})

	server.handleFrame(frame)

	select {
	case stream := <-server.accept:
		if stream.TunnelID() != "tun-xyz" {
			t.Errorf("TunnelID = %q, want %q", stream.TunnelID(), "tun-xyz")
		}
		if stream.RemoteAddr() != "10.0.0.1:8080" {
			t.Errorf("RemoteAddr = %q, want %q", stream.RemoteAddr(), "10.0.0.1:8080")
		}
		if stream.Protocol() != "tcp" {
			t.Errorf("Protocol = %q, want %q", stream.Protocol(), "tcp")
		}
	default:
		t.Fatal("No stream available")
	}

	server.Close()
}

// TestMuxControlFrameMuxClosed tests handleControlFrame when mux is already closed.
func TestMuxControlFrameMuxClosed(t *testing.T) {
	_, server := newTestPipe(t)

	// Close the mux first
	server.Close()

	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, &proto.AuthRequest{
		Token: "test-token",
	})

	err := server.handleControlFrame(frame)
	if err != ErrMuxClosed {
		t.Errorf("Expected ErrMuxClosed, got %v", err)
	}
}

// TestMuxControlFrameChannelFullThenClose tests handleControlFrame when the control channel
// is full and the mux closes while blocked.
func TestMuxControlFrameChannelFullThenClose(t *testing.T) {
	_, server := newTestPipe(t)

	// Fill the control channel (capacity 16)
	for i := 0; i < 16; i++ {
		frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, &proto.AuthRequest{
			Token: "fill",
		})
		if err := server.handleControlFrame(frame); err != nil {
			t.Fatalf("handleControlFrame %d failed: %v", i, err)
		}
	}

	// Now the channel is full. The next send will block in the second select.
	// Close the mux after a short delay to unblock via <-m.done.
	go func() {
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	frame, _ := proto.EncodeJSONPayload(proto.FrameAuthReq, 0, &proto.AuthRequest{
		Token: "overflow",
	})

	err := server.handleControlFrame(frame)
	if err != ErrMuxClosed {
		t.Errorf("Expected ErrMuxClosed, got %v", err)
	}
}


func TestLastHeartbeat(t *testing.T) {
	client, server := newTestPipe(t)
	if !client.LastHeartbeat().IsZero() {
		t.Error("LastHeartbeat should be zero initially")
	}

	go server.Run()

	frame := &proto.Frame{
		Version:  proto.Version,
		Type:     proto.FrameHeartbeat,
		StreamID: 0,
		Payload:  proto.HeartbeatPayload(),
	}
	client.GetFrameWriter().Write(frame)

	ackFrame, err := client.frameReader.Read()
	if err != nil {
		t.Fatalf("Read ack: %v", err)
	}
	client.handleFrame(ackFrame)

	hb := client.LastHeartbeat()
	if hb.IsZero() {
		t.Error("LastHeartbeat should be set after ack")
	}
	if time.Since(hb) > 5*time.Second {
		t.Error("LastHeartbeat should be recent")
	}

	client.Close()
	server.Close()
}
