package safedial

import (
	"net"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// Private IPv4
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.1.100", true},
		// Loopback
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		// Link-local / metadata
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		// Unspecified
		{"0.0.0.0", true},
		// Public IPv4
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.32.0.1", false},
		{"172.15.255.255", false},
		// IPv6 loopback
		{"::1", true},
		// IPv6 unique local
		{"fd00::1", true},
		// IPv6 link-local
		{"fe80::1", true},
		// IPv6 public
		{"2001:db8::1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %s", tt.ip)
		}
		got := isPrivate(ip)
		if got != tt.private {
			t.Errorf("isPrivate(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}
