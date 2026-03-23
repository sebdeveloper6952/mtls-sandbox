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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/config"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/client"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/mock"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ratelimit"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/safedial"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/session"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/store"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ui"
)

// Deps holds optional dependencies injected into the server.
type Deps struct {
	Store         *store.Store
	MockRouter    *mock.Router
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	SessionStore  *session.Store
	RateLimiter   *ratelimit.Limiter
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
	sessionStore  *session.Store
	rateLimiter   *ratelimit.Limiter
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
		sessionStore:  deps.SessionStore,
		rateLimiter:   deps.RateLimiter,
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
	if s.sessionStore != nil {
		healthMux.HandleFunc("/api/sessions", s.createSessionHandler)
		healthMux.HandleFunc("/api/sessions/", s.sessionRouter)
	}
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

// --- Session API handlers ---

func (s *Server) createSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	sess, err := s.sessionStore.Create()
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(sess)
}

// sessionRouter dispatches /api/sessions/{id}[/test|/calls] requests.
func (s *Server) sessionRouter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse: /api/sessions/{id}[/suffix]
	path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	suffix := ""
	if len(parts) == 2 {
		suffix = parts[1]
	}

	if id == "" {
		http.NotFound(w, r)
		return
	}

	switch suffix {
	case "":
		switch r.Method {
		case http.MethodGet:
			s.getSessionHandler(w, r, id)
		case http.MethodPatch:
			s.updateSessionHandler(w, r, id)
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	case "test":
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		s.testSessionHandler(w, r, id)
	case "calls":
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		s.listCallsHandler(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) getSessionHandler(w http.ResponseWriter, r *http.Request, id string) {
	sess, err := s.sessionStore.Get(id)
	if err != nil {
		s.logger.Error("failed to get session", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if sess == nil {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(sess)
}

func (s *Server) updateSessionHandler(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		CallbackURL string `json:"callback_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := validateCallbackURL(body.CallbackURL); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	if err := s.sessionStore.UpdateCallbackURL(id, body.CallbackURL); err != nil {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	sess, err := s.sessionStore.Get(id)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(sess)
}

func (s *Server) testSessionHandler(w http.ResponseWriter, r *http.Request, id string) {
	// Rate limit.
	if s.rateLimiter != nil && !s.rateLimiter.Allow(id) {
		http.Error(w, `{"error":"rate limit exceeded, try again later"}`, http.StatusTooManyRequests)
		return
	}

	sess, err := s.sessionStore.GetWithKey(id)
	if err != nil {
		s.logger.Error("failed to get session", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if sess == nil {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	if sess.CallbackURL == "" {
		http.Error(w, `{"error":"callback_url not set, use PATCH /api/sessions/{id} first"}`, http.StatusBadRequest)
		return
	}

	// Parse test mode from request body (optional).
	mode := session.TestModeNormal
	var body struct {
		TestMode string `json:"test_mode"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body)
	}
	switch session.TestMode(body.TestMode) {
	case session.TestModeNoCert, session.TestModeWrongCA:
		mode = session.TestMode(body.TestMode)
	}

	// Build HTTP client based on test mode.
	clientCfg := client.Config{
		Insecure: true, // We don't validate the user's server cert.
		Timeout:  10 * time.Second,
	}
	switch mode {
	case session.TestModeNormal:
		clientCfg.ClientCertPEM = []byte(sess.CertPEM)
		clientCfg.ClientKeyPEM = []byte(sess.KeyPEM)
	case session.TestModeNoCert:
		// No client cert — server should reject.
	case session.TestModeWrongCA:
		wrongCert, wrongKey, err := s.sessionStore.WrongCACert()
		if err != nil {
			s.logger.Error("failed to get wrong CA cert", "error", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		clientCfg.ClientCertPEM = wrongCert
		clientCfg.ClientKeyPEM = wrongKey
	}

	httpClient, err := client.NewHTTPClient(clientCfg)
	if err != nil {
		s.logger.Error("failed to build HTTP client for session", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Attach SSRF-safe dialer to the transport.
	transport := httpClient.Transport.(*http.Transport)
	dialer := &safedial.SafeDialer{}
	transport.DialContext = dialer.DialContext

	// Make the outbound call.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	probeResult := client.Probe(ctx, httpClient, sess.CallbackURL, nil, nil)

	// Store the call.
	callID, err := s.sessionStore.AddCall(id, sess.CallbackURL, mode, probeResult.StatusCode, probeResult.DurationMS, probeResult.Error, probeResult)
	if err != nil {
		s.logger.Error("failed to store call", "error", err)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"call_id":      callID,
		"test_mode":    mode,
		"callback_url": sess.CallbackURL,
		"status_code":  probeResult.StatusCode,
		"duration_ms":  probeResult.DurationMS,
		"error":        probeResult.Error,
		"inspection":   probeResult.Inspection,
	})
}

func (s *Server) listCallsHandler(w http.ResponseWriter, r *http.Request, id string) {
	limit := 20
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

	calls, total, err := s.sessionStore.ListCalls(id, limit, offset)
	if err != nil {
		s.logger.Error("failed to list calls", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if calls == nil {
		calls = []session.CallRecord{}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"calls": calls,
		"total": total,
	})
}

// validateCallbackURL checks that a callback URL is safe to call.
func validateCallbackURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("callback_url is required")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("callback_url must use https")
	}

	if u.Hostname() == "" {
		return fmt.Errorf("callback_url must have a hostname")
	}

	return nil
}
