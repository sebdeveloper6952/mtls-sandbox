package inspector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testCA holds a CA certificate and key for test helpers.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-ca",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{cert: cert, key: key, pool: pool}
}

// issueClientCert issues a valid client certificate from the test CA.
func (ca *testCA) issueClientCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-client",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// issueExpiredCert issues a client cert that already expired.
func (ca *testCA) issueExpiredCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "expired-client"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// issueNotYetValidCert issues a client cert whose NotBefore is in the future.
func (ca *testCA) issueNotYetValidCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "future-client"},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// issueWeakRSACert issues a client cert with a 1024-bit RSA key.
func (ca *testCA) issueWeakRSACert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "weak-key-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// issueServerOnlyCert issues a cert with only ServerAuth EKU (not ClientAuth).
func (ca *testCA) issueServerOnlyCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "server-only"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func makeTLSState(certs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		ServerName:       "localhost",
		PeerCertificates: certs,
	}
}

func TestInspect_ValidCert(t *testing.T) {
	ca := newTestCA(t)
	clientCert := ca.issueClientCert(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(clientCert),
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if !report.HandshakeOK {
		t.Errorf("expected handshake_ok=true, got false; failure=%s reason=%s", report.FailureCode, report.FailureReason)
	}
	if report.FailureCode != FailureNone {
		t.Errorf("expected no failure code, got %q", report.FailureCode)
	}
	if len(report.Hints) != 0 {
		t.Errorf("expected no hints, got %v", report.Hints)
	}
	if len(report.Presented.CertChain) != 1 {
		t.Errorf("expected 1 cert in chain, got %d", len(report.Presented.CertChain))
	}
	if report.Presented.TLSVersion != "TLS 1.3" {
		t.Errorf("expected TLS 1.3, got %s", report.Presented.TLSVersion)
	}
}

func TestInspect_NoCert(t *testing.T) {
	ca := newTestCA(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(),
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false")
	}
	if report.FailureCode != FailureNoCert {
		t.Errorf("expected failure_code=%q, got %q", FailureNoCert, report.FailureCode)
	}
	if len(report.Hints) == 0 {
		t.Error("expected hints for no_client_cert")
	}

	// Check that hints mention curl.
	found := false
	for _, h := range report.Hints {
		if strings.Contains(h, "curl") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected hints to mention curl")
	}
}

func TestInspect_WrongCA(t *testing.T) {
	serverCA := newTestCA(t)
	otherCA := newTestCA(t)
	clientCert := otherCA.issueClientCert(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(clientCert),
		Mode:       "strict",
		TrustedCA:  serverCA.cert,
		CARootPool: serverCA.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false")
	}
	if report.FailureCode != FailureWrongCA {
		t.Errorf("expected failure_code=%q, got %q", FailureWrongCA, report.FailureCode)
	}
	if len(report.Hints) == 0 {
		t.Error("expected hints for wrong_ca")
	}

	// Hints should mention both CAs.
	hintsJoined := strings.Join(report.Hints, " ")
	if !strings.Contains(hintsJoined, "test-ca") {
		t.Error("expected hints to mention the CA name")
	}
}

func TestInspect_Expired(t *testing.T) {
	ca := newTestCA(t)
	expiredCert := ca.issueExpiredCert(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(expiredCert),
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false")
	}
	if report.FailureCode != FailureExpired {
		t.Errorf("expected failure_code=%q, got %q", FailureExpired, report.FailureCode)
	}
	if len(report.Hints) == 0 {
		t.Error("expected hints for expired cert")
	}
}

func TestInspect_NotYetValid(t *testing.T) {
	ca := newTestCA(t)
	futureCert := ca.issueNotYetValidCert(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(futureCert),
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false")
	}
	if report.FailureCode != FailureNotYetValid {
		t.Errorf("expected failure_code=%q, got %q", FailureNotYetValid, report.FailureCode)
	}
}

func TestInspect_WeakRSAKey(t *testing.T) {
	ca := newTestCA(t)
	weakCert := ca.issueWeakRSACert(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(weakCert),
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false")
	}
	if report.FailureCode != FailureWeakKey {
		t.Errorf("expected failure_code=%q, got %q", FailureWeakKey, report.FailureCode)
	}

	hintsJoined := strings.Join(report.Hints, " ")
	if !strings.Contains(hintsJoined, "RSA") {
		t.Error("expected hints to mention RSA")
	}
	if !strings.Contains(hintsJoined, "2048") {
		t.Error("expected hints to mention 2048")
	}
}

func TestInspect_NoClientAuthEKU(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueServerOnlyCert(t)

	report := Inspect(InspectParams{
		TLSState:   makeTLSState(serverCert),
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false")
	}
	if report.FailureCode != FailureNoClientAuth {
		t.Errorf("expected failure_code=%q, got %q", FailureNoClientAuth, report.FailureCode)
	}
}

func TestInspect_NilTLSState(t *testing.T) {
	ca := newTestCA(t)

	report := Inspect(InspectParams{
		TLSState:   nil,
		Mode:       "strict",
		TrustedCA:  ca.cert,
		CARootPool: ca.pool,
	})

	if report.HandshakeOK {
		t.Error("expected handshake_ok=false for nil TLS state")
	}
	if report.FailureCode != FailureNoCert {
		t.Errorf("expected failure_code=%q, got %q", FailureNoCert, report.FailureCode)
	}
}

func TestBuildCertInfo(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueClientCert(t)

	info := BuildCertInfo(cert)

	if info.Subject != "test-client" {
		t.Errorf("expected subject=test-client, got %s", info.Subject)
	}
	if info.Issuer != "test-ca" {
		t.Errorf("expected issuer=test-ca, got %s", info.Issuer)
	}
	if info.KeyType != "ECDSA" {
		t.Errorf("expected key_type=ECDSA, got %s", info.KeyType)
	}
	if info.KeyBits != 256 {
		t.Errorf("expected key_bits=256, got %d", info.KeyBits)
	}
	if !info.HasClientAuthEKU {
		t.Error("expected has_client_auth_eku=true")
	}
	if info.IsExpired {
		t.Error("expected is_expired=false")
	}
	if len(info.DNSNames) == 0 {
		t.Error("expected DNS names")
	}
	if len(info.IPAddresses) == 0 {
		t.Error("expected IP addresses")
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0, "unknown"},
	}

	for _, tt := range tests {
		if got := TLSVersionName(tt.version); got != tt.name {
			t.Errorf("TLSVersionName(%d) = %q, want %q", tt.version, got, tt.name)
		}
	}
}
