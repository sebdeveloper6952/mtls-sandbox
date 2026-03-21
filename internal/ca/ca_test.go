package ca

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
)

func TestNewCA_ECDSA(t *testing.T) {
	authority, err := NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	if !authority.Cert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if authority.Cert.Subject.CommonName != "mtls-sandbox-ca" {
		t.Errorf("expected CN=mtls-sandbox-ca, got %s", authority.Cert.Subject.CommonName)
	}
	if authority.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert should have KeyUsageCertSign")
	}

	// Verify self-signed.
	pool := x509.NewCertPool()
	pool.AddCert(authority.Cert)
	if _, err := authority.Cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("CA cert should be self-signed and verifiable: %v", err)
	}
}

func TestNewCA_RSA(t *testing.T) {
	authority, err := NewCA("rsa-4096")
	if err != nil {
		t.Fatal(err)
	}
	if !authority.Cert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
}

func TestNewCA_InvalidAlgo(t *testing.T) {
	_, err := NewCA("rsa-1024")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestIssueCert_Server(t *testing.T) {
	authority, err := NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	certPEM, _, err := authority.IssueCert("server", "test-server", []string{"localhost", "127.0.0.1", "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	cert := parsePEMCert(t, certPEM)

	if cert.Subject.CommonName != "test-server" {
		t.Errorf("expected CN=test-server, got %s", cert.Subject.CommonName)
	}

	// Check ExtKeyUsage.
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("server cert should have ExtKeyUsageServerAuth")
	}

	// Check DNS SANs.
	foundLocalhost := false
	foundExample := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
		if name == "example.com" {
			foundExample = true
		}
	}
	if !foundLocalhost {
		t.Error("expected localhost in DNS SANs")
	}
	if !foundExample {
		t.Error("expected example.com in DNS SANs")
	}

	// Check IP SANs.
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Error("expected 127.0.0.1 in IP SANs")
	}

	// Verify chain.
	pool := x509.NewCertPool()
	pool.AddCert(authority.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("server cert should verify against CA: %v", err)
	}
}

func TestIssueCert_Client(t *testing.T) {
	authority, err := NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	certPEM, _, err := authority.IssueCert("client", "test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	cert := parsePEMCert(t, certPEM)

	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("client cert should have ExtKeyUsageClientAuth")
	}

	pool := x509.NewCertPool()
	pool.AddCert(authority.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert should verify against CA: %v", err)
	}
}

func TestIssueCert_InvalidRole(t *testing.T) {
	authority, err := NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = authority.IssueCert("invalid", "test", nil)
	if err == nil {
		t.Error("expected error for invalid role")
	}
}

func TestPersistAndLoad(t *testing.T) {
	authority, err := NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverKey, err := authority.IssueCert("server", "srv", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}

	clientCert, clientKey, err := authority.IssueCert("client", "cli", nil)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := Persist(dir, authority.CertPEM, authority.KeyPEM, serverCert, serverKey, clientCert, clientKey); err != nil {
		t.Fatal(err)
	}

	// Load the CA back.
	loaded, err := LoadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Cert.Subject.CommonName != authority.Cert.Subject.CommonName {
		t.Errorf("loaded CA CN mismatch: got %s, want %s",
			loaded.Cert.Subject.CommonName, authority.Cert.Subject.CommonName)
	}

	// Verify loaded CA can issue new certs.
	_, _, err = loaded.IssueCert("client", "new-client", nil)
	if err != nil {
		t.Errorf("loaded CA should be able to issue certs: %v", err)
	}
}

func parsePEMCert(t *testing.T, pemData []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}
