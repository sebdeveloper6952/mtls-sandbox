package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/config"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ca"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/store"
)

type testEnv struct {
	cfg           *config.Config
	caCertPEM     []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

func setupTestEnv(t *testing.T, mode string) *testEnv {
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

	cfg := config.Defaults()
	cfg.Mode = mode
	cfg.Port = 0       // random port
	cfg.HealthPort = 0 // random port
	cfg.Log.Format = "text"

	return &testEnv{
		cfg:           cfg,
		caCertPEM:     authority.CertPEM,
		serverCertPEM: serverCert,
		serverKeyPEM:  serverKey,
		clientCertPEM: clientCert,
		clientKeyPEM:  clientKey,
	}
}

func startServer(t *testing.T, env *testEnv) (mtlsURL, healthURL string, cancel context.CancelFunc) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reqStore, _ := store.NewStore(100, "")
	srv, err := New(env.cfg, env.caCertPEM, env.serverCertPEM, env.serverKeyPEM, logger, Deps{
		Store:         reqStore,
		ClientCertPEM: env.clientCertPEM,
		ClientKeyPEM:  env.clientKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	errCh := make(chan error, 2)

	go func() {
		if err := srv.Run(ctx); err != nil {
			errCh <- err
		}
	}()

	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		cancelFn()
		time.Sleep(100 * time.Millisecond)
	})

	return fmt.Sprintf("https://localhost:%d", env.cfg.Port),
		fmt.Sprintf("http://localhost:%d", env.cfg.HealthPort),
		cancelFn
}

func (env *testEnv) tlsClientWithCert(t *testing.T) *http.Client {
	t.Helper()

	clientCert, err := tls.X509KeyPair(env.clientCertPEM, env.clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(env.caCertPEM)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
			},
		},
		Timeout: 5 * time.Second,
	}
}

func (env *testEnv) tlsClientWithoutCert(t *testing.T) *http.Client {
	t.Helper()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(env.caCertPEM)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
		Timeout: 5 * time.Second,
	}
}

// tlsClientWithWrongCert creates a client with a cert from a different CA.
func (env *testEnv) tlsClientWithWrongCert(t *testing.T) *http.Client {
	t.Helper()

	// Generate a second CA and issue a client cert from it.
	otherCA, err := ca.NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	otherClientCert, otherClientKey, err := otherCA.IssueCert("client", "wrong-ca-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, err := tls.X509KeyPair(otherClientCert, otherClientKey)
	if err != nil {
		t.Fatal(err)
	}

	// Trust the server's CA for the TLS connection, but present certs from the wrong CA.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(env.caCertPEM)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
			},
		},
		Timeout: 5 * time.Second,
	}
}

func TestStrictWithCert(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18443
	env.cfg.HealthPort = 18080

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %v", body["status"])
	}
	if body["message"] != "mTLS handshake successful" {
		t.Errorf("expected mTLS success message, got %v", body["message"])
	}
}

func TestStrictWithoutCert(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18444
	env.cfg.HealthPort = 18081

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithoutCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["handshake_ok"] != false {
		t.Errorf("expected handshake_ok=false, got %v", body["handshake_ok"])
	}
	if body["failure_code"] != "no_client_cert" {
		t.Errorf("expected failure_code=no_client_cert, got %v", body["failure_code"])
	}
	hints, ok := body["hints"].([]any)
	if !ok || len(hints) == 0 {
		t.Error("expected hints in response")
	}
}

func TestStrictWithWrongCACert(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18451
	env.cfg.HealthPort = 18088

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithWrongCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["failure_code"] != "wrong_ca" {
		t.Errorf("expected failure_code=wrong_ca, got %v", body["failure_code"])
	}
	hints, ok := body["hints"].([]any)
	if !ok || len(hints) == 0 {
		t.Error("expected hints in response")
	}
}

func TestLenientWithoutCert(t *testing.T) {
	env := setupTestEnv(t, "lenient")
	env.cfg.Port = 18445
	env.cfg.HealthPort = 18082

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithoutCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-MTLS-Warning") == "" {
		t.Error("expected X-MTLS-Warning header in lenient mode without cert")
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	// Lenient mode wraps the inspection report under "inspection".
	inspection, ok := body["inspection"].(map[string]any)
	if !ok {
		t.Fatal("expected inspection field in response")
	}
	if inspection["handshake_ok"] != false {
		t.Errorf("expected handshake_ok=false in inspection, got %v", inspection["handshake_ok"])
	}
}

func TestLenientWithCert(t *testing.T) {
	env := setupTestEnv(t, "lenient")
	env.cfg.Port = 18446
	env.cfg.HealthPort = 18083

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-MTLS-Warning") != "" {
		t.Error("should not have X-MTLS-Warning when cert is provided")
	}
}

func TestInspectWithoutCert(t *testing.T) {
	env := setupTestEnv(t, "inspect")
	env.cfg.Port = 18447
	env.cfg.HealthPort = 18084

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithoutCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["handshake_ok"] != false {
		t.Errorf("expected handshake_ok=false, got %v", body["handshake_ok"])
	}
	if body["failure_code"] != "no_client_cert" {
		t.Errorf("expected failure_code=no_client_cert, got %v", body["failure_code"])
	}
}

func TestInspectWithCert(t *testing.T) {
	env := setupTestEnv(t, "inspect")
	env.cfg.Port = 18448
	env.cfg.HealthPort = 18085

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	client := env.tlsClientWithCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["handshake_ok"] != true {
		t.Errorf("expected handshake_ok=true, got %v", body["handshake_ok"])
	}
	presented, ok := body["presented"].(map[string]any)
	if !ok {
		t.Fatal("expected presented field")
	}
	certChain, ok := presented["cert_chain"].([]any)
	if !ok || len(certChain) == 0 {
		t.Error("expected cert_chain in presented")
	}
}

func TestDebugEndpoint(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18452
	env.cfg.HealthPort = 18089

	mtlsURL, _, cancel := startServer(t, env)
	defer cancel()

	// Without cert — should still get a report (not a TLS rejection).
	client := env.tlsClientWithoutCert(t)
	resp, err := client.Get(mtlsURL + "/debug")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	if body["handshake_ok"] != false {
		t.Errorf("expected handshake_ok=false, got %v", body["handshake_ok"])
	}
	if body["failure_code"] != "no_client_cert" {
		t.Errorf("expected failure_code=no_client_cert, got %v", body["failure_code"])
	}

	// With cert — should succeed.
	clientWithCert := env.tlsClientWithCert(t)
	resp2, err := clientWithCert.Get(mtlsURL + "/debug")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	var body2 map[string]any
	json.NewDecoder(resp2.Body).Decode(&body2)
	if body2["handshake_ok"] != true {
		t.Errorf("expected handshake_ok=true, got %v", body2["handshake_ok"])
	}
}

func TestHealthEndpoint(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18449
	env.cfg.HealthPort = 18086

	_, healthURL, cancel := startServer(t, env)
	defer cancel()

	resp, err := http.Get(healthURL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %v", body["status"])
	}
}

func TestStatusEndpoint(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18460
	env.cfg.HealthPort = 18461

	_, healthURL, cancel := startServer(t, env)
	defer cancel()

	resp, err := http.Get(healthURL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["mode"] != "strict" {
		t.Errorf("expected mode strict, got %v", body["mode"])
	}
	if body["mtls_port"] == nil {
		t.Error("expected mtls_port in status")
	}
}

func TestCertsEndpoint(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18462
	env.cfg.HealthPort = 18463

	_, healthURL, cancel := startServer(t, env)
	defer cancel()

	resp, err := http.Get(healthURL + "/api/certs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)

	for _, role := range []string{"ca", "server", "client"} {
		cert, ok := body[role].(map[string]any)
		if !ok {
			t.Errorf("expected %s cert info", role)
			continue
		}
		if cert["cn"] == nil {
			t.Errorf("expected cn for %s cert", role)
		}
		if cert["pem"] == nil {
			t.Errorf("expected pem for %s cert", role)
		}
	}

	// Client should have key_pem
	client := body["client"].(map[string]any)
	if client["key_pem"] == nil {
		t.Error("expected key_pem for client cert")
	}
}

func TestRequestsEndpoint(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18464
	env.cfg.HealthPort = 18465

	mtlsURL, healthURL, cancel := startServer(t, env)
	defer cancel()

	// Make a request to the mTLS server to generate a log entry.
	client := env.tlsClientWithCert(t)
	resp, err := client.Get(mtlsURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Give recording middleware time to write.
	time.Sleep(50 * time.Millisecond)

	// Check the request log.
	resp, err = http.Get(healthURL + "/api/requests")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var entries []map[string]any
	json.NewDecoder(resp.Body).Decode(&entries)

	if len(entries) == 0 {
		t.Fatal("expected at least one request entry")
	}

	entry := entries[0]
	if entry["method"] != "GET" {
		t.Errorf("expected GET, got %v", entry["method"])
	}
	if entry["path"] != "/" {
		t.Errorf("expected /, got %v", entry["path"])
	}

	// Test individual entry retrieval.
	id := entry["id"].(string)
	resp2, err := http.Get(healthURL + "/api/requests/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestDashboardServed(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18466
	env.cfg.HealthPort = 18467

	_, healthURL, cancel := startServer(t, env)
	defer cancel()

	resp, err := http.Get(healthURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "mTLS Sandbox") {
		t.Error("expected dashboard HTML to contain 'mTLS Sandbox'")
	}
}

func TestGracefulShutdown(t *testing.T) {
	env := setupTestEnv(t, "strict")
	env.cfg.Port = 18450
	env.cfg.HealthPort = 18087

	_, _, cancel := startServer(t, env)

	// Cancel and verify server stops.
	cancel()
	time.Sleep(200 * time.Millisecond)

	// After shutdown, connections should be refused.
	_, err := http.Get(fmt.Sprintf("http://localhost:%d/health", env.cfg.HealthPort))
	if err == nil {
		t.Error("expected connection refused after shutdown")
	}
}
