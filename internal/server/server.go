package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/config"
)

type Server struct {
	cfg          *config.Config
	tlsConfig    *tls.Config
	httpServer   *http.Server
	healthServer *http.Server
	logger       *slog.Logger
	caCert       *x509.Certificate
	caPool       *x509.CertPool
}

// New creates a Server configured for mTLS on cfg.Port and a plain HTTP health
// server on cfg.HealthPort.
func New(cfg *config.Config, caCertPEM, serverCertPEM, serverKeyPEM []byte, logger *slog.Logger) (*Server, error) {
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to add CA cert to pool")
	}

	// Parse CA certificate for use by the inspector.
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	// All modes use RequestClientCert so the HTTP handler always runs.
	// Certificate verification is done manually in the handler via the
	// inspector package, which produces structured diagnostic feedback.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	s := &Server{
		cfg:       cfg,
		tlsConfig: tlsCfg,
		logger:    logger,
		caCert:    caCert,
		caPool:    caPool,
	}

	mux := http.NewServeMux()
	mux.Handle("/debug", s.loggingMiddleware(s.debugHandler()))
	mux.Handle("/", s.loggingMiddleware(s.modeHandler()))

	s.httpServer = &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.Port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	s.healthServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HealthPort),
		Handler: healthMux,
	}

	return s, nil
}

// Run starts both the mTLS and health servers, blocking until ctx is cancelled.
// It performs graceful shutdown with a 5-second deadline.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		s.logger.Info("starting mTLS server",
			"port", s.cfg.Port,
			"mode", s.cfg.Mode,
		)
		ln, err := net.Listen("tcp", s.httpServer.Addr)
		if err != nil {
			errCh <- fmt.Errorf("mTLS listen: %w", err)
			return
		}
		tlsLn := tls.NewListener(ln, s.tlsConfig)
		if err := s.httpServer.Serve(tlsLn); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("mTLS server: %w", err)
		}
	}()

	go func() {
		s.logger.Info("starting health server", "port", s.cfg.HealthPort)
		if err := s.healthServer.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("health server: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	s.logger.Info("shutting down servers")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("mTLS server shutdown error", "error", err)
	}
	if err := s.healthServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("health server shutdown error", "error", err)
	}

	return nil
}
