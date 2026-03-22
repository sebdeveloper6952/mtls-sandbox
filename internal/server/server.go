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
	"strconv"
	"strings"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/config"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/mock"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/store"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ui"
)

// Deps holds optional dependencies injected into the server.
type Deps struct {
	Store         *store.Store
	MockRouter    *mock.Router
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

type Server struct {
	cfg          *config.Config
	tlsConfig    *tls.Config
	httpServer   *http.Server
	healthServer *http.Server
	logger       *slog.Logger
	caCert       *x509.Certificate
	caPool       *x509.CertPool

	store         *store.Store
	mockRouter    *mock.Router
	caCertPEM     []byte
	serverCertPEM []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
	startedAt     time.Time
}

// New creates a Server configured for mTLS on cfg.Port and a plain HTTP health
// server on cfg.HealthPort.
func New(cfg *config.Config, caCertPEM, serverCertPEM, serverKeyPEM []byte, logger *slog.Logger, deps Deps) (*Server, error) {
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
		cfg:           cfg,
		tlsConfig:     tlsCfg,
		logger:        logger,
		caCert:        caCert,
		caPool:        caPool,
		store:         deps.Store,
		mockRouter:    deps.MockRouter,
		caCertPEM:     caCertPEM,
		serverCertPEM: serverCertPEM,
		clientCertPEM: deps.ClientCertPEM,
		clientKeyPEM:  deps.ClientKeyPEM,
	}

	// mTLS server routes.
	mux := http.NewServeMux()
	mainHandler := http.Handler(s.modeHandler())
	if s.mockRouter != nil {
		// Wire mock router's fallthrough to modeHandler.
		s.mockRouter.SetNext(s.modeHandler())
		mainHandler = s.mockRouter
	}
	mux.Handle("/debug", s.recordingMiddleware(s.loggingMiddleware(s.debugHandler())))
	mux.Handle("/", s.recordingMiddleware(s.loggingMiddleware(mainHandler)))

	s.httpServer = &http.Server{
		Addr:      fmt.Sprintf(":%d", cfg.Port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	// Health / dashboard / API server routes.
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	healthMux.HandleFunc("/api/status", s.statusHandler)
	healthMux.HandleFunc("/api/certs", s.certsHandler)
	healthMux.HandleFunc("/api/certs/ca", s.rawCertHandler(s.caCertPEM, "ca.crt"))
	healthMux.HandleFunc("/api/certs/client", s.rawCertHandler(s.clientCertPEM, "client.crt"))
	healthMux.HandleFunc("/api/certs/client-key", s.rawCertHandler(s.clientKeyPEM, "client.key"))
	healthMux.HandleFunc("/api/requests", s.listRequestsHandler)
	healthMux.HandleFunc("/api/requests/", s.getRequestHandler)
	healthMux.Handle("/", ui.Handler())

	s.healthServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HealthPort),
		Handler: healthMux,
	}

	return s, nil
}

// Run starts both the mTLS and health servers, blocking until ctx is cancelled.
// It performs graceful shutdown with a 5-second deadline.
func (s *Server) Run(ctx context.Context) error {
	s.startedAt = time.Now()
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

// --- Health API handlers ---

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"mode":           s.cfg.Mode,
		"uptime_seconds": int(time.Since(s.startedAt).Seconds()),
		"started_at":     s.startedAt.Format(time.RFC3339),
		"mtls_port":      s.cfg.Port,
		"health_port":    s.cfg.HealthPort,
		"persist_path":   s.cfg.TLS.PersistPath,
	})
}

func (s *Server) certsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	certInfo := func(pemBytes []byte) map[string]any {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return map[string]any{"error": "invalid PEM"}
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{
			"cn":        cert.Subject.CommonName,
			"issuer":    cert.Issuer.CommonName,
			"not_after": cert.NotAfter.Format(time.RFC3339),
			"dns_names": cert.DNSNames,
			"pem":       string(pemBytes),
		}
	}

	resp := map[string]any{
		"ca":     certInfo(s.caCertPEM),
		"server": certInfo(s.serverCertPEM),
	}

	clientInfo := certInfo(s.clientCertPEM)
	clientInfo["key_pem"] = string(s.clientKeyPEM)
	resp["client"] = clientInfo

	json.NewEncoder(w).Encode(resp)
}

func (s *Server) rawCertHandler(pemData []byte, filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		w.Write(pemData)
	}
}

func (s *Server) listRequestsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.store == nil {
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	entries := s.store.List(limit, offset)
	if entries == nil {
		entries = []store.RequestEntry{}
	}
	json.NewEncoder(w).Encode(entries)
}

func (s *Server) getRequestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.store == nil {
		http.NotFound(w, r)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/requests/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	entry, ok := s.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	json.NewEncoder(w).Encode(entry)
}
