package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/inspector"
)

// Config holds the certificate material and settings for an outbound mTLS client.
type Config struct {
	CACertPEM     []byte        // CA to trust for server verification (nil = system roots)
	ClientCertPEM []byte        // client cert to present
	ClientKeyPEM  []byte        // client key
	Insecure      bool          // skip server cert verification
	Timeout       time.Duration // request timeout (default 10s)
}

// PingResult is the concise result of a ping operation.
type PingResult struct {
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	ServerCN   string `json:"server_cn,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// ProbeResult is the full diagnostic result of a probe operation.
type ProbeResult struct {
	URL        string                      `json:"url"`
	DurationMS int64                       `json:"duration_ms"`
	StatusCode int                         `json:"status_code,omitempty"`
	Error      string                      `json:"error,omitempty"`
	Inspection *inspector.InspectionReport `json:"inspection,omitempty"`
}

// NewHTTPClient builds an *http.Client configured for mTLS using the given Config.
func NewHTTPClient(cfg Config) (*http.Client, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure,
	}

	// Load client certificate if provided.
	if len(cfg.ClientCertPEM) > 0 && len(cfg.ClientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Set trusted CA pool if provided.
	if len(cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, fmt.Errorf("failed to add CA cert to pool")
		}
		tlsCfg.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   timeout,
	}, nil
}

// Ping makes a single GET request and returns a concise result.
func Ping(ctx context.Context, httpClient *http.Client, url string) *PingResult {
	result := &PingResult{URL: url}
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.DurationMS = time.Since(start).Milliseconds()
		result.Error = err.Error()
		return result
	}

	resp, err := httpClient.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	result.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	result.StatusCode = resp.StatusCode

	if resp.TLS != nil {
		result.TLSVersion = inspector.TLSVersionName(resp.TLS.Version)
		if len(resp.TLS.PeerCertificates) > 0 {
			result.ServerCN = resp.TLS.PeerCertificates[0].Subject.CommonName
		}
	}

	return result
}

// Probe makes a GET request and runs the full inspector analysis on the server's
// TLS configuration. trustedCA and caPool are optional — when nil, chain
// verification against a specific CA is skipped.
func Probe(ctx context.Context, httpClient *http.Client, url string, trustedCA *x509.Certificate, caPool *x509.CertPool) *ProbeResult {
	result := &ProbeResult{URL: url}
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.DurationMS = time.Since(start).Milliseconds()
		result.Error = err.Error()
		return result
	}

	resp, err := httpClient.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	result.StatusCode = resp.StatusCode

	// Run inspector on the server's TLS state.
	result.Inspection = inspector.Inspect(inspector.InspectParams{
		TLSState:   resp.TLS,
		Mode:       "probe",
		TrustedCA:  trustedCA,
		CARootPool: caPool,
		Direction:  "outbound",
	})

	return result
}

// ParseCACert parses a PEM-encoded CA certificate into an x509.Certificate and CertPool.
func ParseCACert(caPEM []byte) (*x509.Certificate, *x509.CertPool, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, pool, nil
}
