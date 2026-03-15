package proto

import (
	"encoding/json"
	"time"
)

// AuthRequest is sent by the client to authenticate.
type AuthRequest struct {
	Token    string `json:"token"`
	ClientID string `json:"client_id,omitempty"`
	Version  string `json:"version,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// AuthResponse is sent by the server after authentication.
type AuthResponse struct {
	OK                 bool   `json:"ok"`
	SessionID          string `json:"session_id,omitempty"`
	ServerVersion      string `json:"server_version,omitempty"`
	HeartbeatInterval  int    `json:"heartbeat_interval_ms,omitempty"`
	MaxTunnels         int    `json:"max_tunnels,omitempty"`
	MaxStreamsPerTunnel int   `json:"max_streams_per_tunnel,omitempty"`
	Error              string `json:"error,omitempty"`
}

// TunnelType represents the type of tunnel.
type TunnelType string

const (
	TunnelTypeHTTP TunnelType = "http"
	TunnelTypeTCP  TunnelType = "tcp"
)

// TunnelAuth represents authentication for a tunnel.
type TunnelAuth struct {
	Type     string `json:"type,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// TunnelRequest is sent by the client to open a tunnel.
type TunnelRequest struct {
	Type       TunnelType        `json:"type"`
	Subdomain  string            `json:"subdomain,omitempty"`
	RemotePort int               `json:"remote_port,omitempty"`
	LocalAddr  string            `json:"local_addr"`
	Inspect    bool              `json:"inspect,omitempty"`
	Auth       *TunnelAuth       `json:"auth,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	AllowedIPs []string          `json:"allowed_ips,omitempty"`
	PIN        string            `json:"pin,omitempty"`
}

// TunnelMetadata contains tunnel-specific metadata.
type TunnelMetadata struct {
	RemotePort int    `json:"remote_port,omitempty"`
	Subdomain  string `json:"subdomain,omitempty"`
}

// TunnelResponse is sent by the server after tunnel allocation.
type TunnelResponse struct {
	OK        bool           `json:"ok"`
	TunnelID  string         `json:"tunnel_id,omitempty"`
	Type      TunnelType     `json:"type,omitempty"`
	PublicURL string         `json:"public_url,omitempty"`
	Metadata  *TunnelMetadata `json:"metadata,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// TunnelClose is sent to close a tunnel.
type TunnelClose struct {
	TunnelID string `json:"tunnel_id"`
}

// StreamOpen is sent by the server when a new connection arrives.
type StreamOpen struct {
	TunnelID   string `json:"tunnel_id"`
	StreamID   uint32 `json:"stream_id"`
	RemoteAddr string `json:"remote_addr"`
	Protocol   string `json:"protocol"`
}

// StreamWindow is sent to update flow control window.
type StreamWindow struct {
	StreamID uint32 `json:"stream_id"`
	Delta    uint32 `json:"delta"`
}

// GoAway is sent to signal graceful shutdown.
type GoAway struct {
	Reason          string `json:"reason"`
	Message         string `json:"message,omitempty"`
	ReconnectAfter  int    `json:"reconnect_after_ms,omitempty"`
}

// ErrorFrame represents a protocol-level error.
type ErrorFrame struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// HeartbeatPayload creates a heartbeat payload with current timestamp.
func HeartbeatPayload() []byte {
	buf := make([]byte, 8)
	ts := uint64(time.Now().UnixNano())
	for i := 0; i < 8; i++ {
		buf[i] = byte(ts >> (56 - i*8))
	}
	return buf
}

// ParseHeartbeat extracts timestamp from heartbeat payload.
func ParseHeartbeat(payload []byte) time.Time {
	if len(payload) < 8 {
		return time.Time{}
	}
	ts := uint64(0)
	for i := 0; i < 8; i++ {
		ts = (ts << 8) | uint64(payload[i])
	}
	return time.Unix(0, int64(ts))
}

// EncodeJSONPayload creates a frame with JSON-encoded payload.
func EncodeJSONPayload(frameType FrameType, streamID uint32, v any) (*Frame, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Frame{
		Version:  Version,
		Type:     frameType,
		StreamID: streamID,
		Payload:  payload,
	}, nil
}

// DecodeJSONPayload decodes JSON payload into v.
func DecodeJSONPayload(f *Frame, v any) error {
	return json.Unmarshal(f.Payload, v)
}
