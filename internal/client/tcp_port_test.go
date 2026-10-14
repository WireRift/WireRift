package client

import (
	"testing"

	"github.com/wirerift/wirerift/internal/proto"
)

// TestAssignedTCPPort covers the port the client reports for a created TCP
// tunnel. The server-assigned port is only carried in PublicURL, so it must
// be parsed from there; everything else falls back to the requested port.
func TestAssignedTCPPort(t *testing.T) {
	tests := []struct {
		name       string
		tunnelType proto.TunnelType
		publicURL  string
		remotePort int
		want       int
	}{
		{
			name:       "parses assigned port from PublicURL",
			tunnelType: proto.TunnelTypeTCP,
			publicURL:  "tcp://wirerift.com:20042",
			remotePort: 0,
			want:       20042,
		},
		{
			name:       "public URL without port falls back to request",
			tunnelType: proto.TunnelTypeTCP,
			publicURL:  "tcp://wirerift.com",
			remotePort: 1234,
			want:       1234,
		},
		{
			name:       "empty PublicURL falls back to request",
			tunnelType: proto.TunnelTypeTCP,
			publicURL:  "",
			remotePort: 1234,
			want:       1234,
		},
		{
			name:       "non-numeric port falls back to request",
			tunnelType: proto.TunnelTypeTCP,
			publicURL:  "tcp://wirerift.com:notaport",
			remotePort: 1234,
			want:       1234,
		},
		{
			name:       "zero port in PublicURL falls back to request",
			tunnelType: proto.TunnelTypeTCP,
			publicURL:  "tcp://wirerift.com:0",
			remotePort: 1234,
			want:       1234,
		},
		{
			name:       "HTTP tunnels keep requested value",
			tunnelType: proto.TunnelTypeHTTP,
			publicURL:  "http://myapp.wirerift.com",
			remotePort: 0,
			want:       0,
		},
		{
			name:       "unparseable PublicURL falls back to request",
			tunnelType: proto.TunnelTypeTCP,
			publicURL:  "://bad",
			remotePort: 1234,
			want:       1234,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := assignedTCPPort(tt.tunnelType, tt.publicURL, tt.remotePort); got != tt.want {
				t.Errorf("assignedTCPPort(%v, %q, %d) = %d, want %d",
					tt.tunnelType, tt.publicURL, tt.remotePort, got, tt.want)
			}
		})
	}
}
