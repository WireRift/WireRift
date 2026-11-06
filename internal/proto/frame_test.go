package proto

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameTypeString(t *testing.T) {
	tests := []struct {
		ft       FrameType
		expected string
	}{
		{FrameAuthReq, "AUTH_REQ"},
		{FrameAuthRes, "AUTH_RES"},
		{FrameTunnelReq, "TUNNEL_REQ"},
		{FrameTunnelRes, "TUNNEL_RES"},
		{FrameTunnelClose, "TUNNEL_CLOSE"},
		{FrameStreamOpen, "STREAM_OPEN"},
		{FrameStreamData, "STREAM_DATA"},
		{FrameStreamClose, "STREAM_CLOSE"},
		{FrameStreamRst, "STREAM_RST"},
		{FrameStreamWindow, "STREAM_WINDOW"},
		{FrameHeartbeat, "HEARTBEAT"},
		{FrameHeartbeatAck, "HEARTBEAT_ACK"},
		{FrameGoAway, "GO_AWAY"},
		{FrameError, "ERROR"},
		{FrameType(0x99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.ft.String(); got != tt.expected {
			t.Errorf("FrameType(%#x).String() = %q, want %q", tt.ft, got, tt.expected)
		}
	}
}

func TestFrameEncodeDecode(t *testing.T) {
	tests := []struct {
		name    string
		frame   *Frame
		wantErr bool
	}{
		{
			name: "empty payload",
			frame: &Frame{
				Version:  Version,
				Type:     FrameHeartbeat,
				StreamID: 0,
				Payload:  nil,
			},
		},
		{
			name: "1 byte payload",
			frame: &Frame{
				Version:  Version,
				Type:     FrameStreamData,
				StreamID: 1,
				Payload:  []byte{0x42},
			},
		},
		{
			name: "small payload",
			frame: &Frame{
				Version:  Version,
				Type:     FrameStreamData,
				StreamID: 42,
				Payload:  []byte("hello"),
			},
		},
		{
			name: "control stream",
			frame: &Frame{
				Version:  Version,
				Type:     FrameAuthReq,
				StreamID: ControlStreamID,
				Payload:  []byte(`{"token":"test"}`),
			},
		},
		{
			name: "max stream ID",
			frame: &Frame{
				Version:  Version,
				Type:     FrameStreamData,
				StreamID: MaxStreamID,
				Payload:  []byte("max stream"),
			},
		},
		{
			name: "large payload",
			frame: &Frame{
				Version:  Version,
				Type:     FrameStreamData,
				StreamID: 100,
				Payload:  make([]byte, 64*1024), // 64 KB
			},
		},
		{
			name: "all frame types",
			frame: &Frame{
				Version:  Version,
				Type:     FrameError,
				StreamID: 0,
				Payload:  []byte(`{"error":"test"}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Encode
			err := tt.frame.Encode(&buf)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("Encode failed: %v", err)
			}

			// Decode
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame failed: %v", err)
			}

			// Compare
			if got.Version != tt.frame.Version {
				t.Errorf("Version = %d, want %d", got.Version, tt.frame.Version)
			}
			if got.Type != tt.frame.Type {
				t.Errorf("Type = %v, want %v", got.Type, tt.frame.Type)
			}
			if got.StreamID != tt.frame.StreamID {
				t.Errorf("StreamID = %d, want %d", got.StreamID, tt.frame.StreamID)
			}
			if !bytes.Equal(got.Payload, tt.frame.Payload) {
				t.Errorf("Payload = %v, want %v", got.Payload, tt.frame.Payload)
			}
		})
	}
}

func TestFrameEncodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		frame   *Frame
		wantErr error
	}{
		{
			name: "invalid version",
			frame: &Frame{
				Version:  0x02,
				Type:     FrameStreamData,
				StreamID: 1,
				Payload:  nil,
			},
			wantErr: ErrInvalidVersion,
		},
		{
			name: "invalid stream ID",
			frame: &Frame{
				Version:  Version,
				Type:     FrameStreamData,
				StreamID: MaxStreamID + 1,
				Payload:  nil,
			},
			wantErr: ErrInvalidStreamID,
		},
		{
			name: "payload too large",
			frame: &Frame{
				Version:  Version,
				Type:     FrameStreamData,
				StreamID: 1,
				Payload:  make([]byte, MaxPayloadSize+1),
			},
			wantErr: ErrPayloadTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tt.frame.Encode(&buf)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err != tt.wantErr {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestFrameReaderWriter(t *testing.T) {
	var buf bytes.Buffer

	fw := NewFrameWriter(&buf)
	fr := NewFrameReader(&buf)

	frames := []*Frame{
		{Version: Version, Type: FrameAuthReq, StreamID: 0, Payload: []byte(`{"token":"abc"}`)},
		{Version: Version, Type: FrameAuthRes, StreamID: 0, Payload: []byte(`{"ok":true}`)},
		{Version: Version, Type: FrameStreamData, StreamID: 1, Payload: []byte("data1")},
		{Version: Version, Type: FrameStreamData, StreamID: 2, Payload: []byte("data2")},
		{Version: Version, Type: FrameStreamClose, StreamID: 1, Payload: nil},
	}

	// Write all frames
	for _, f := range frames {
		if err := fw.Write(f); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	// Read all frames
	for i, want := range frames {
		got, err := fr.Read()
		if err != nil {
			t.Fatalf("Read [%d] failed: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("[%d] Type = %v, want %v", i, got.Type, want.Type)
		}
		if got.StreamID != want.StreamID {
			t.Errorf("[%d] StreamID = %d, want %d", i, got.StreamID, want.StreamID)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("[%d] Payload = %v, want %v", i, got.Payload, want.Payload)
		}
	}
}

func TestMagicReadWrite(t *testing.T) {
	var buf bytes.Buffer

	// Write magic
	if err := WriteMagic(&buf); err != nil {
		t.Fatalf("WriteMagic failed: %v", err)
	}

	// Read and validate magic
	if err := ReadMagic(&buf); err != nil {
		t.Fatalf("ReadMagic failed: %v", err)
	}
}

type oneByteWriter struct{ bytes.Buffer }

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

func TestProtocolWritesHandleShortNilWrites(t *testing.T) {
	frame := &Frame{Version: Version, Type: FrameStreamData, StreamID: 7, Payload: []byte("payload")}
	w := &oneByteWriter{}
	if err := frame.Encode(w); err != nil {
		t.Fatalf("Encode returned an error while short writes made progress: %v", err)
	}
	if got, want := w.Len(), HeaderSize+len(frame.Payload); got != want {
		t.Fatalf("encoded %d bytes, want %d", got, want)
	}
	decoded, err := ReadFrame(bytes.NewReader(w.Bytes()))
	if err != nil || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatalf("short-write frame did not round-trip: frame=%v err=%v", decoded, err)
	}

	magic := &oneByteWriter{}
	if err := WriteMagic(magic); err != nil {
		t.Fatalf("WriteMagic returned an error while short writes made progress: %v", err)
	}
	if !bytes.Equal(magic.Bytes(), Magic) {
		t.Fatalf("magic = %x, want %x", magic.Bytes(), Magic)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestProtocolWritesRejectZeroProgress(t *testing.T) {
	frame := &Frame{Version: Version, Type: FrameHeartbeat}
	if err := frame.Encode(zeroWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Encode error = %v, want io.ErrShortWrite", err)
	}
	if err := WriteMagic(zeroWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteMagic error = %v, want io.ErrShortWrite", err)
	}
}

func TestReadMagicInvalid(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00, 0x00, 0x00, 0x00})
	err := ReadMagic(buf)
	if err != ErrInvalidMagic {
		t.Errorf("error = %v, want %v", err, ErrInvalidMagic)
	}
}

func BenchmarkFrameEncode(b *testing.B) {
	frame := &Frame{
		Version:  Version,
		Type:     FrameStreamData,
		StreamID: 1,
		Payload:  make([]byte, 1024),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		frame.Encode(&buf)
	}
}

func BenchmarkFrameDecode(b *testing.B) {
	frame := &Frame{
		Version:  Version,
		Type:     FrameStreamData,
		StreamID: 1,
		Payload:  make([]byte, 1024),
	}

	var buf bytes.Buffer
	frame.Encode(&buf)
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(data)
		ReadFrame(r)
	}
}

// TestReadFrameErrors tests ReadFrame error handling
func TestReadFrameErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "invalid version",
			data:    []byte{0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: ErrInvalidVersion,
		},
		{
			name:    "payload too large",
			data:    []byte{Version, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01},
			wantErr: ErrPayloadTooLarge,
		},
		{
			name:    "header too short",
			data:    []byte{Version, 0x01, 0x00, 0x00},
			wantErr: io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewReader(tt.data)
			_, err := ReadFrame(buf)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && err != tt.wantErr {
				// Some errors wrap the underlying error
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

// TestReadMagicInsufficientData tests ReadMagic with insufficient data
func TestReadMagicInsufficientData(t *testing.T) {
	// Less than 4 bytes
	buf := bytes.NewBuffer([]byte{0x57, 0x52})
	err := ReadMagic(buf)
	if err == nil {
		t.Error("expected error for insufficient data")
	}
}

// errWriter is a writer that fails after writing a specified number of bytes.
type errWriter struct {
	failAfter int // fail after this many bytes
	written   int
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.written+len(p) > ew.failAfter {
		// Allow partial write up to failAfter
		n := ew.failAfter - ew.written
		if n <= 0 {
			return 0, errors.New("write error")
		}
		ew.written += n
		return n, errors.New("write error")
	}
	ew.written += len(p)
	return len(p), nil
}

// TestEncodeHeaderWriteError tests Encode when the header write fails
func TestEncodeHeaderWriteError(t *testing.T) {
	frame := &Frame{
		Version:  Version,
		Type:     FrameStreamData,
		StreamID: 1,
		Payload:  []byte("hello"),
	}

	// Writer that fails immediately
	w := &errWriter{failAfter: 0}
	err := frame.Encode(w)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestEncodePayloadWriteError tests Encode when the payload write fails
func TestEncodePayloadWriteError(t *testing.T) {
	frame := &Frame{
		Version:  Version,
		Type:     FrameStreamData,
		StreamID: 1,
		Payload:  []byte("hello"),
	}

	// Writer that succeeds on header (9 bytes) but fails on payload
	w := &errWriter{failAfter: HeaderSize}
	err := frame.Encode(w)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestReadFramePayloadReadError tests ReadFrame with truncated payload
func TestReadFramePayloadReadError(t *testing.T) {
	// Build a valid header that says payload is 10 bytes, but only provide 5 bytes of payload
	header := make([]byte, HeaderSize)
	header[0] = Version
	header[1] = byte(FrameStreamData)
	header[2] = 0 // streamID high
	header[3] = 0 // streamID mid
	header[4] = 1 // streamID low
	// Payload length = 10
	header[5] = 0
	header[6] = 0
	header[7] = 0
	header[8] = 10

	// Only 5 bytes of payload
	data := append(header, make([]byte, 5)...)
	buf := bytes.NewReader(data)

	_, err := ReadFrame(buf)
	if err == nil {
		t.Fatal("expected error for truncated payload, got nil")
	}
}

// TestReadMagicPartialInvalid tests ReadMagic with partially invalid magic
func TestReadMagicPartialInvalid(t *testing.T) {
	// First two bytes correct, last two wrong
	buf := bytes.NewBuffer([]byte{0x57, 0x52, 0x00, 0x00})
	err := ReadMagic(buf)
	if err != ErrInvalidMagic {
		t.Errorf("error = %v, want %v", err, ErrInvalidMagic)
	}
}
