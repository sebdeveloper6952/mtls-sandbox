package inspector

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// FailureCode identifies the specific failure type for programmatic use.
type FailureCode string

const (
	FailureNone         FailureCode = ""
	FailureNoCert       FailureCode = "no_client_cert"
	FailureWrongCA      FailureCode = "wrong_ca"
	FailureExpired      FailureCode = "cert_expired"
	FailureNotYetValid  FailureCode = "cert_not_yet_valid"
	FailureWeakKey      FailureCode = "weak_key"
	FailureNoClientAuth FailureCode = "no_client_auth_eku"
	FailureNoServerAuth FailureCode = "no_server_auth_eku"
)

// CertInfo holds a serializable summary of an X.509 certificate.
type CertInfo struct {
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	Serial          string   `json:"serial"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	DNSNames        []string `json:"dns_names,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	KeyType         string   `json:"key_type"`
	KeyBits         int      `json:"key_bits"`
	IsExpired       bool     `json:"is_expired"`
	HasClientAuthEKU bool    `json:"has_client_auth_eku"`
}

// Expected describes what the server requires from the client.
type Expected struct {
	ClientAuth string `json:"client_auth"`
	TrustedCA  string `json:"trusted_ca"`
}

// Presented describes what the client actually sent during the TLS handshake.
type Presented struct {
	CertChain   []CertInfo `json:"cert_chain"`
	TLSVersion  string     `json:"tls_version"`
	CipherSuite string     `json:"cipher_suite"`
	ServerName  string     `json:"server_name"`
}

// InspectionReport is the structured diagnostic output of an mTLS connection analysis.
type InspectionReport struct {
	HandshakeOK   bool        `json:"handshake_ok"`
	FailureCode   FailureCode `json:"failure_code,omitempty"`
	FailureReason string      `json:"failure_reason,omitempty"`
	Expected      Expected    `json:"expected"`
	Presented     Presented   `json:"presented"`
	Hints         []string    `json:"hints,omitempty"`
	Timestamp     string      `json:"timestamp"`
}

// InspectParams holds the inputs needed to produce an InspectionReport.
type InspectParams struct {
	TLSState   *tls.ConnectionState
	Mode       string
	TrustedCA  *x509.Certificate
	CARootPool *x509.CertPool
	Direction  string // "inbound" (default/empty) or "outbound"
}

// Inspect analyzes TLS connection state and produces a diagnostic report.
// Direction "outbound" checks the server's certificate (for ping/probe);
// empty or "inbound" checks the client's certificate (default server behavior).
func Inspect(params InspectParams) *InspectionReport {
	now := time.Now()
	outbound := params.Direction == "outbound"
	certLabel := "client"
	if outbound {
		certLabel = "server"
	}

	report := &InspectionReport{
		Timestamp: now.Format(time.RFC3339),
		Expected: Expected{
			ClientAuth: params.Mode,
		},
	}

	if params.TrustedCA != nil {
		report.Expected.TrustedCA = params.TrustedCA.Subject.CommonName
	}

	// No TLS state at all.
	if params.TLSState == nil {
		report.FailureCode = FailureNoCert
		report.FailureReason = "connection is not TLS"
		report.Hints = GenerateHints(FailureNoCert, nil, report.Expected.TrustedCA)
		return report
	}

	// Populate presented TLS info.
	report.Presented.TLSVersion = TLSVersionName(params.TLSState.Version)
	report.Presented.CipherSuite = tls.CipherSuiteName(params.TLSState.CipherSuite)
	report.Presented.ServerName = params.TLSState.ServerName

	// Build cert chain info.
	for _, cert := range params.TLSState.PeerCertificates {
		report.Presented.CertChain = append(report.Presented.CertChain, BuildCertInfo(cert))
	}

	// Check 1: No peer certificates.
	if len(params.TLSState.PeerCertificates) == 0 {
		report.FailureCode = FailureNoCert
		report.FailureReason = certLabel + " certificate not presented"
		report.Hints = GenerateHints(FailureNoCert, nil, report.Expected.TrustedCA)
		return report
	}

	peer := params.TLSState.PeerCertificates[0]
	peerInfo := BuildCertInfo(peer)

	// Check 2: Weak key.
	if isWeakKey(peer) {
		report.FailureCode = FailureWeakKey
		report.FailureReason = fmt.Sprintf("%s certificate uses a weak key: %s %d-bit", certLabel, peerInfo.KeyType, peerInfo.KeyBits)
		report.Hints = GenerateHints(FailureWeakKey, &peerInfo, report.Expected.TrustedCA)
		return report
	}

	// Check 3: Expired.
	if now.After(peer.NotAfter) {
		report.FailureCode = FailureExpired
		report.FailureReason = fmt.Sprintf("%s certificate expired on %s", certLabel, peer.NotAfter.Format(time.RFC3339))
		report.Hints = GenerateHints(FailureExpired, &peerInfo, report.Expected.TrustedCA)
		return report
	}

	// Check 4: Not yet valid.
	if now.Before(peer.NotBefore) {
		report.FailureCode = FailureNotYetValid
		report.FailureReason = fmt.Sprintf("%s certificate is not valid until %s", certLabel, peer.NotBefore.Format(time.RFC3339))
		report.Hints = GenerateHints(FailureNotYetValid, &peerInfo, report.Expected.TrustedCA)
		return report
	}

	// Check 5: EKU check (direction-dependent).
	if outbound {
		if !hasServerAuthEKU(peer) {
			report.FailureCode = FailureNoServerAuth
			report.FailureReason = "server certificate does not include the ServerAuth extended key usage"
			report.Hints = GenerateHints(FailureNoServerAuth, &peerInfo, report.Expected.TrustedCA)
			return report
		}
	} else {
		if !hasClientAuthEKU(peer) {
			report.FailureCode = FailureNoClientAuth
			report.FailureReason = "client certificate does not include the ClientAuth extended key usage"
			report.Hints = GenerateHints(FailureNoClientAuth, &peerInfo, report.Expected.TrustedCA)
			return report
		}
	}

	// Check 6: Chain verification (wrong CA).
	if params.CARootPool != nil {
		eku := x509.ExtKeyUsageClientAuth
		if outbound {
			eku = x509.ExtKeyUsageServerAuth
		}
		_, err := peer.Verify(x509.VerifyOptions{
			Roots:     params.CARootPool,
			KeyUsages: []x509.ExtKeyUsage{eku},
		})
		if err != nil {
			report.FailureCode = FailureWrongCA
			report.FailureReason = fmt.Sprintf("%s certificate chain verification failed: %v", certLabel, err)
			report.Hints = GenerateHints(FailureWrongCA, &peerInfo, report.Expected.TrustedCA)
			return report
		}
	}

	// All checks passed.
	report.HandshakeOK = true
	return report
}

// BuildCertInfo extracts a serializable summary from an x509.Certificate.
func BuildCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		Serial:    cert.SerialNumber.String(),
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		DNSNames:  cert.DNSNames,
		IsExpired: time.Now().After(cert.NotAfter),
		HasClientAuthEKU: hasClientAuthEKU(cert),
	}

	info.IPAddresses = FormatIPs(cert)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		info.KeyBits = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.KeyType = "Ed25519"
		info.KeyBits = 256
	default:
		info.KeyType = "unknown"
	}

	return info
}

// TLSVersionName returns a human-readable name for a TLS version constant.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

// FormatIPs returns the IP SANs of a certificate as strings.
func FormatIPs(cert *x509.Certificate) []string {
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return ips
}

func isWeakKey(cert *x509.Certificate) bool {
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		return pub.N.BitLen() < 2048
	}
	return false
}

func hasClientAuthEKU(cert *x509.Certificate) bool {
	// If no EKUs are specified, we don't flag it — some CAs issue certs
	// without explicit EKUs and they work fine with Go's TLS stack.
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func hasServerAuthEKU(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
