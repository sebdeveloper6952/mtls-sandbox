package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/ca"
)

type testEnv struct {
	authority     *ca.CA
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	authority, err := ca.NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverKey, err := authority.IssueCert("server", "test-server", []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	clientCert, clientKey, err := authority.IssueCert("client", "test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	return &testEnv{
		authority:     authority,
		serverCertPEM: serverCert,
		serverKeyPEM:  serverKey,
		clientCertPEM: clientCert,
		clientKeyPEM:  clientKey,
	}
}

// startTestMTLSServer starts a TLS server that requires client certs.
// Returns the URL and a cleanup function.
func startTestMTLSServer(t *testing.T, env *testEnv) string {
	t.Helper()

	serverCert, err := tls.X509KeyPair(env.serverCertPEM, env.serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(env.authority.CertPEM)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &http.Server{Handler: mux}

	go srv.Serve(tlsLn)
	t.Cleanup(func() {
		srv.Close()
	})

	return fmt.Sprintf("https://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
}

func TestNewHTTPClient_WithCerts(t *testing.T) {
	env := setupTestEnv(t)

	httpClient, err := NewHTTPClient(Config{
		CACertPEM:     env.authority.CertPEM,
		ClientCertPEM: env.clientCertPEM,
		ClientKeyPEM:  env.clientKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	transport := httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLS config")
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Error("expected client certificate loaded")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected root CAs set")
	}
}

func TestNewHTTPClient_Insecure(t *testing.T) {
	httpClient, err := NewHTTPClient(Config{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}

	transport := httpClient.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

func TestPing_Success(t *testing.T) {
	env := setupTestEnv(t)
	url := startTestMTLSServer(t, env)

	httpClient, err := NewHTTPClient(Config{
		CACertPEM:     env.authority.CertPEM,
		ClientCertPEM: env.clientCertPEM,
		ClientKeyPEM:  env.clientKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := Ping(context.Background(), httpClient, url+"/")

	if !result.OK {
		t.Errorf("expected OK, got error: %s", result.Error)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if result.TLSVersion == "" {
		t.Error("expected TLS version")
	}
	if result.ServerCN != "test-server" {
		t.Errorf("expected CN=test-server, got %s", result.ServerCN)
	}
	if result.DurationMS <= 0 {
		t.Error("expected positive duration")
	}
}

func TestPing_ConnectionRefused(t *testing.T) {
	httpClient, _ := NewHTTPClient(Config{Insecure: true})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := Ping(ctx, httpClient, "https://127.0.0.1:1/unreachable")

	if result.OK {
		t.Error("expected failure")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestProbe_Success(t *testing.T) {
	env := setupTestEnv(t)
	url := startTestMTLSServer(t, env)

	httpClient, err := NewHTTPClient(Config{
		CACertPEM:     env.authority.CertPEM,
		ClientCertPEM: env.clientCertPEM,
		ClientKeyPEM:  env.clientKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	caCert, caPool, _ := ParseCACert(env.authority.CertPEM)
	result := Probe(context.Background(), httpClient, url+"/", caCert, caPool)

	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if result.Inspection == nil {
		t.Fatal("expected inspection report")
	}
	if !result.Inspection.HandshakeOK {
		t.Errorf("expected handshake OK, got failure: %s", result.Inspection.FailureReason)
	}
	if len(result.Inspection.Presented.CertChain) == 0 {
		t.Error("expected server cert chain in inspection")
	}
}

func TestProbe_Insecure(t *testing.T) {
	env := setupTestEnv(t)
	url := startTestMTLSServer(t, env)

	// Use insecure mode (no CA) with client cert.
	httpClient, err := NewHTTPClient(Config{
		ClientCertPEM: env.clientCertPEM,
		ClientKeyPEM:  env.clientKeyPEM,
		Insecure:      true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Probe without CA for chain verification — should still get TLS state.
	result := Probe(context.Background(), httpClient, url+"/", nil, nil)

	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.Inspection == nil {
		t.Fatal("expected inspection report")
	}
	// Without CA pool, chain verification is skipped, so handshake should be OK.
	if !result.Inspection.HandshakeOK {
		t.Errorf("expected handshake OK with insecure + no CA pool, got: %s", result.Inspection.FailureReason)
	}
}

func TestParseCACert(t *testing.T) {
	env := setupTestEnv(t)

	cert, pool, err := ParseCACert(env.authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Error("expected cert")
	}
	if pool == nil {
		t.Error("expected pool")
	}
	if cert.Subject.CommonName != "mtls-sandbox-ca" {
		t.Errorf("expected CN=mtls-sandbox-ca, got %s", cert.Subject.CommonName)
	}
}
