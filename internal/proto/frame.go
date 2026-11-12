package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// Errors returned by the proto package.
var (
	ErrInvalidVersion  = errors.New("invalid protocol version")
	ErrInvalidStreamID = errors.New("invalid stream ID")
	ErrPayloadTooLarge = errors.New("payload exceeds maximum size")
	ErrInvalidMagic    = errors.New("invalid magic bytes")
)

// Frame represents a single protocol frame.
type Frame struct {
	Version  byte      // Protocol version (currently 0x01)
	Type     FrameType // Frame type
	StreamID uint32    // Stream identifier (0 = control stream)
	Payload  []byte    // Frame payload (0 to 16 MB)
}

// headerPool is a pool for reusing header buffers.
var headerPool = sync.Pool{
	New: func() any {
		b := make([]byte, HeaderSize)
		return &b
	},
}

// Encode writes the frame to the provided writer.
func (f *Frame) Encode(w io.Writer) error {
	// Validate frame
	if f.Version != Version {
		return ErrInvalidVersion
	}
	if f.StreamID > MaxStreamID {
		return ErrInvalidStreamID
	}
	if len(f.Payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}

	// Get header buffer from pool
	headerp := headerPool.Get().(*[]byte)
	header := *headerp
	defer headerPool.Put(headerp)

	// Encode header
	header[0] = f.Version
	header[1] = byte(f.Type)
	header[2] = byte(f.StreamID >> 16)                              // Stream ID high byte
	header[3] = byte(f.StreamID >> 8)                               // Stream ID mid byte
	header[4] = byte(f.StreamID)                                    // Stream ID low byte
	binary.BigEndian.PutUint32(header[5:9], uint32(len(f.Payload))) //nolint:gosec // payload length is bounded by MaxPayloadSize

	// Write header
	if err := writeFull(w, header); err != nil {
		return err
	}

	// Write payload (if any)
	if len(f.Payload) > 0 {
		if err := writeFull(w, f.Payload); err != nil {
			return err
		}
	}

	return nil
}

// writeFull writes all of p or returns the first error. io.Writer permits a
// short write with a nil error, which must not be reported as a complete
// protocol frame.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ReadFrame reads a frame from the provided reader.
func ReadFrame(r io.Reader) (*Frame, error) {
	// Get header buffer from pool
	headerp := headerPool.Get().(*[]byte)
	header := *headerp
	defer headerPool.Put(headerp)

	// Read header
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	// Parse header
	version := header[0]
	if version != Version {
		return nil, ErrInvalidVersion
	}

	frameType := FrameType(header[1])

	// Stream ID is 3 bytes big-endian, max value is 0xFFFFFF == MaxStreamID
	streamID := uint32(header[2])<<16 | uint32(header[3])<<8 | uint32(header[4])

	payloadLen := binary.BigEndian.Uint32(header[5:9])
	if payloadLen > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		var err error
		if payloadLen <= smallPayloadSize {
			payload = make([]byte, payloadLen)
			_, err = io.ReadFull(r, payload)
		} else {
			// Don't trust the claimed length for a large allocation: grow as
			// data actually arrives, so a bare header costs nothing.
			var buf bytes.Buffer
			_, err = io.CopyN(&buf, r, int64(payloadLen))
			payload = buf.Bytes()
		}
		if err == io.EOF {
			// The header promised payload bytes: ending here is a truncated
			// frame, never a clean end of stream.
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
	}

	return &Frame{
		Version:  version,
		Type:     frameType,
		StreamID: streamID,
		Payload:  payload,
	}, nil
}

// smallPayloadSize is the largest payload allocated up front from the header.
const smallPayloadSize = 64 * 1024

// FrameReader wraps an io.Reader for reading frames.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader creates a new FrameReader.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// Read reads and returns the next frame.
func (fr *FrameReader) Read() (*Frame, error) {
	return ReadFrame(fr.r)
}

// FrameWriter wraps an io.Writer for writing frames with thread safety.
type FrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewFrameWriter creates a new FrameWriter.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// Write writes a frame to the underlying writer. Thread-safe.
func (fw *FrameWriter) Write(f *Frame) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return f.Encode(fw.w)
}

// WriteMagic writes the magic bytes to identify the protocol.
func WriteMagic(w io.Writer) error {
	return writeFull(w, Magic)
}

// ReadMagic reads and validates magic bytes.
func ReadMagic(r io.Reader) error {
	buf := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	for i, b := range buf {
		if b != Magic[i] {
			return ErrInvalidMagic
		}
	}
	return nil
}
