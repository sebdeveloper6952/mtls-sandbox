package safedial

import (
	"context"
	"fmt"
	"net"
)

// ErrPrivateIP is returned when the resolved address is a private or reserved IP.
var ErrPrivateIP = fmt.Errorf("connection to private/reserved IP address is not allowed")

// SafeDialer wraps a net.Dialer and rejects connections to private IP ranges.
// This prevents SSRF attacks when making outbound HTTP requests on behalf of users.
type SafeDialer struct {
	inner net.Dialer
}

// DialContext resolves the address and checks whether it falls into a private
// or reserved IP range before connecting. It tries each resolved IP in order
// (IPv4 first) to work around environments without IPv6 connectivity.
func (d *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	// Filter out private IPs and sort IPv4 before IPv6 for reliability.
	var allowed []net.IPAddr
	for _, ip := range ips {
		if isPrivate(ip.IP) {
			return nil, ErrPrivateIP
		}
		allowed = append(allowed, ip)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	sortIPv4First(allowed)

	// Try each resolved address in order, falling through on error.
	var lastErr error
	for _, ip := range allowed {
		conn, err := d.inner.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// Stop if the context is done (timeout or cancellation).
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// sortIPv4First reorders addresses so IPv4 comes before IPv6.
func sortIPv4First(ips []net.IPAddr) {
	i := 0
	for j := range ips {
		if ips[j].IP.To4() != nil {
			ips[i], ips[j] = ips[j], ips[i]
			i++
		}
	}
}

func isPrivate(ip net.IP) bool {
	// Normalize to 4-byte form if IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	privateRanges := []net.IPNet{
		// IPv4 private
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		// IPv4 loopback
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		// IPv4 link-local
		{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
		// IPv6 loopback
		{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
		// IPv6 unique local (fc00::/7)
		{IP: net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(7, 128)},
		// IPv6 link-local (fe80::/10)
		{IP: net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(10, 128)},
	}

	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}

	return ip.IsUnspecified()
}
