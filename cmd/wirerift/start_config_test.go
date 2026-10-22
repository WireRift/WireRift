package main

import (
	"strings"
	"testing"
)

// TestValidateTunnelConfigs pins fail-fast validation of configured
// local_ports: `wirerift start` must reject out-of-range ports before
// creating any tunnel, matching the interactive CLI's 1-65535 check.
func TestValidateTunnelConfigs(t *testing.T) {
	tests := []struct {
		name      string
		ports     []int
		wantErr   bool
		errSubstr string
	}{
		{name: "valid single port", ports: []int{8080}},
		{name: "boundary 1", ports: []int{1}},
		{name: "boundary 65535", ports: []int{65535}},
		{name: "zero port rejected", ports: []int{0}, wantErr: true, errSubstr: "tunnel 1"},
		{name: "negative port rejected", ports: []int{-1}, wantErr: true, errSubstr: "tunnel 1"},
		{name: "port above 65535 rejected", ports: []int{99999}, wantErr: true, errSubstr: "99999"},
		{name: "valid tunnel then invalid tunnel fails with index", ports: []int{18472, 99999}, wantErr: true, errSubstr: "tunnel 2"},
		{name: "invalid tunnel then valid tunnel fails fast", ports: []int{0, 8080}, wantErr: true, errSubstr: "tunnel 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnels := make([]TunnelConfig, len(tt.ports))
			for i, p := range tt.ports {
				tunnels[i] = TunnelConfig{Type: "http", LocalPort: p}
			}
			err := validateTunnelConfigs(&ConfigFile{Tunnels: tunnels})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateTunnelConfigs(%v) = nil, want error", tt.ports)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not mention %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateTunnelConfigs(%v) = %v, want nil", tt.ports, err)
			}
		})
	}
}

func TestValidateTunnelConfigsTunnelType(t *testing.T) {
	for _, typ := range []string{"", "http", "tcp"} {
		if err := validateTunnelConfigs(&ConfigFile{Tunnels: []TunnelConfig{{Type: typ, LocalPort: 8080}}}); err != nil {
			t.Errorf("type %q: unexpected error %v", typ, err)
		}
	}
	err := validateTunnelConfigs(&ConfigFile{Tunnels: []TunnelConfig{{Type: "http", LocalPort: 80}, {Type: "tpc", LocalPort: 8080}}})
	if err == nil || !strings.Contains(err.Error(), "tunnel 2") || !strings.Contains(err.Error(), "tpc") {
		t.Fatalf("typo'd type: err = %v, want an error naming tunnel 2 and %q", err, "tpc")
	}
}
