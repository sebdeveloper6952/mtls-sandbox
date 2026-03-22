package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
	"syscall"

	"github.com/sebdeveloper6952/mtls-sandbox/config"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ca"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/client"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/mock"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ratelimit"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/server"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/session"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/store"
)

func main() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		runServe(os.Args[1:])
		return
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "ping":
		runPing(os.Args[2:])
	case "probe":
		runProbe(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Usage: mtls-sandbox <command> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve   Start the mTLS server (default)\n")
		fmt.Fprintf(os.Stderr, "  ping    Make a single mTLS request to a URL\n")
		fmt.Fprintf(os.Stderr, "  probe   Full mTLS diagnostic of a remote server\n")
		os.Exit(1)
	}
}

// --- serve ---

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config YAML file")
	ephemeral := fs.Bool("ephemeral", false, "do not persist generated certificates to disk")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if *ephemeral {
		cfg.TLS.PersistPath = ""
	}

	logger := setupLogger(cfg)

	authority, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM, err := initCA(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize CA", "error", err)
		os.Exit(1)
	}

	ca.PrintBundle(os.Stdout, authority.CertPEM, serverCertPEM, clientCertPEM)

	if cfg.TLS.PersistPath != "" {
		if err := ca.Persist(cfg.TLS.PersistPath, authority.CertPEM, authority.KeyPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM); err != nil {
			logger.Error("failed to persist certificates", "error", err)
			os.Exit(1)
		}
		logger.Info("certificates persisted", "path", cfg.TLS.PersistPath)
	}

	// Initialize request store.
	reqStore, err := store.NewStore(cfg.Store.Capacity, cfg.Store.LogFile)
	if err != nil {
		logger.Error("failed to initialize request store", "error", err)
		os.Exit(1)
	}
	defer reqStore.Close()

	// Load mock routes if configured.
	var mockRouter *mock.Router
	if cfg.Mock.RoutesFile != "" {
		mockCfg, err := mock.LoadRoutes(cfg.Mock.RoutesFile)
		if err != nil {
			logger.Error("failed to load mock routes", "error", err)
			os.Exit(1)
		}
		mockRouter, err = mock.NewRouter(mockCfg, nil)
		if err != nil {
			logger.Error("failed to compile mock routes", "error", err)
			os.Exit(1)
		}
		logger.Info("mock routes loaded", "file", cfg.Mock.RoutesFile, "routes", len(mockCfg.Routes))
	}

	// Initialize session store if enabled.
	var sessStore *session.Store
	var limiter *ratelimit.Limiter
	if cfg.Session.Enabled {
		maxAge, err := time.ParseDuration(cfg.Session.MaxAge)
		if err != nil {
			logger.Error("invalid session max_age", "error", err)
			os.Exit(1)
		}
		sessStore, err = session.NewStore(cfg.Session.DBPath, authority, maxAge)
		if err != nil {
			logger.Error("failed to initialize session store", "error", err)
			os.Exit(1)
		}
		defer sessStore.Close()

		rateWindow, err := time.ParseDuration(cfg.Session.RateWindow)
		if err != nil {
			logger.Error("invalid session rate_window", "error", err)
			os.Exit(1)
		}
		limiter = ratelimit.New(cfg.Session.RateLimit, rateWindow)

		// Background cleanup of expired sessions.
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				if n, err := sessStore.CleanExpired(); err != nil {
					logger.Error("session cleanup error", "error", err)
				} else if n > 0 {
					logger.Info("cleaned expired sessions", "count", n)
				}
			}
		}()

		logger.Info("session store initialized", "db", cfg.Session.DBPath, "max_age", cfg.Session.MaxAge)
	}

	srv, err := server.New(cfg, authority.CertPEM, serverCertPEM, serverKeyPEM, logger, server.Deps{
		Store:         reqStore,
		MockRouter:    mockRouter,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		SessionStore:  sessStore,
		RateLimiter:   limiter,
	})
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// --- ping ---

func runPing(args []string) {
	cf := newClientFlags("ping")
	cf.fs.Parse(args)

	url := cf.fs.Arg(0)
	if url == "" {
		fmt.Fprintf(os.Stderr, "Usage: mtls-sandbox ping [flags] <url>\n")
		os.Exit(1)
	}

	httpClient, err := cf.buildHTTPClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result := client.Ping(context.Background(), httpClient, url)

	if result.OK {
		fmt.Printf("OK  %d  %s  CN=%s  %s  %dms\n",
			result.StatusCode, result.TLSVersion, result.ServerCN, result.URL, result.DurationMS)
	} else {
		errMsg := result.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP %d", result.StatusCode)
		}
		fmt.Printf("FAIL  %s  %s  %dms\n", errMsg, result.URL, result.DurationMS)
		os.Exit(1)
	}
}

// --- probe ---

func runProbe(args []string) {
	cf := newClientFlags("probe")
	cf.fs.Parse(args)

	url := cf.fs.Arg(0)
	if url == "" {
		fmt.Fprintf(os.Stderr, "Usage: mtls-sandbox probe [flags] <url>\n")
		os.Exit(1)
	}

	httpClient, caCert, caPool, err := cf.buildHTTPClientWithCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result := client.Probe(context.Background(), httpClient, url, caCert, caPool)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)

	if result.Inspection == nil || !result.Inspection.HandshakeOK {
		os.Exit(1)
	}
}

// --- shared client flags ---

type clientFlags struct {
	fs       *flag.FlagSet
	caPath   string
	certPath string
	keyPath  string
	insecure bool
}

func newClientFlags(name string) *clientFlags {
	cf := &clientFlags{
		fs: flag.NewFlagSet(name, flag.ExitOnError),
	}
	cf.fs.StringVar(&cf.caPath, "ca", "", "path to CA certificate PEM file")
	cf.fs.StringVar(&cf.certPath, "cert", "", "path to client certificate PEM file")
	cf.fs.StringVar(&cf.keyPath, "key", "", "path to client key PEM file")
	cf.fs.BoolVar(&cf.insecure, "insecure", false, "skip server certificate verification")
	return cf
}

func (cf *clientFlags) loadCerts() (caPEM, certPEM, keyPEM []byte, err error) {
	// If explicit cert/key paths are provided, use those.
	if cf.certPath != "" && cf.keyPath != "" {
		certPEM, err = os.ReadFile(cf.certPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading client cert: %w", err)
		}
		keyPEM, err = os.ReadFile(cf.keyPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading client key: %w", err)
		}
		if cf.caPath != "" {
			caPEM, err = os.ReadFile(cf.caPath)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("reading CA cert: %w", err)
			}
		}
		return caPEM, certPEM, keyPEM, nil
	}

	// Otherwise, try loading from the default persist path.
	persistPath := "./certs"
	caFile := filepath.Join(persistPath, "ca.crt")
	certFile := filepath.Join(persistPath, "client.crt")
	keyFile := filepath.Join(persistPath, "client.key")

	if fileExists(certFile) && fileExists(keyFile) {
		certPEM, err = os.ReadFile(certFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading client cert: %w", err)
		}
		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading client key: %w", err)
		}
		if fileExists(caFile) {
			caPEM, _ = os.ReadFile(caFile)
		}
		return caPEM, certPEM, keyPEM, nil
	}

	// Generate ephemeral certs.
	authority, err := ca.NewCA("ecdsa-p256")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating ephemeral CA: %w", err)
	}
	certPEM, keyPEM, err = authority.IssueCert("client", "mtls-sandbox-client", nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issuing ephemeral client cert: %w", err)
	}
	return authority.CertPEM, certPEM, keyPEM, nil
}

func (cf *clientFlags) buildHTTPClient() (*http.Client, error) {
	caPEM, certPEM, keyPEM, err := cf.loadCerts()
	if err != nil {
		return nil, err
	}

	return client.NewHTTPClient(client.Config{
		CACertPEM:     caPEM,
		ClientCertPEM: certPEM,
		ClientKeyPEM:  keyPEM,
		Insecure:      cf.insecure,
	})
}

func (cf *clientFlags) buildHTTPClientWithCA() (*http.Client, *x509.Certificate, *x509.CertPool, error) {
	caPEM, certPEM, keyPEM, err := cf.loadCerts()
	if err != nil {
		return nil, nil, nil, err
	}

	httpClient, err := client.NewHTTPClient(client.Config{
		CACertPEM:     caPEM,
		ClientCertPEM: certPEM,
		ClientKeyPEM:  keyPEM,
		Insecure:      cf.insecure,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	if len(caPEM) > 0 {
		caCert, caPool, err := client.ParseCACert(caPEM)
		if err != nil {
			return nil, nil, nil, err
		}
		return httpClient, caCert, caPool, nil
	}

	return httpClient, nil, nil, nil
}

// --- CA initialization (for serve) ---

func initCA(cfg *config.Config, logger *slog.Logger) (authority *ca.CA, serverCert, serverKey, clientCert, clientKey []byte, err error) {
	if cfg.TLS.CACert != "" && cfg.TLS.CAKey != "" {
		logger.Info("loading user-provided CA", "cert", cfg.TLS.CACert, "key", cfg.TLS.CAKey)
		authority, err = ca.LoadCA(cfg.TLS.CACert, cfg.TLS.CAKey)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("loading CA: %w", err)
		}
		serverCert, serverKey, clientCert, clientKey, err = loadOrIssue(cfg, authority, logger)
		return
	}

	if cfg.TLS.PersistPath != "" {
		caCertPath := filepath.Join(cfg.TLS.PersistPath, "ca.crt")
		caKeyPath := filepath.Join(cfg.TLS.PersistPath, "ca.key")
		if fileExists(caCertPath) && fileExists(caKeyPath) {
			logger.Info("loading existing CA from disk", "path", cfg.TLS.PersistPath)
			authority, err = ca.LoadCA(caCertPath, caKeyPath)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("loading CA from disk: %w", err)
			}
			serverCert, serverKey, clientCert, clientKey, err = loadOrIssue(cfg, authority, logger)
			return
		}
	}

	logger.Info("generating new CA and certificates")
	authority, err = ca.NewCA("ecdsa-p256")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("generating CA: %w", err)
	}

	serverCert, serverKey, err = authority.IssueCert("server", "mtls-sandbox-server", cfg.Hostnames)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("issuing server cert: %w", err)
	}

	clientCert, clientKey, err = authority.IssueCert("client", "mtls-sandbox-client", nil)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("issuing client cert: %w", err)
	}

	return authority, serverCert, serverKey, clientCert, clientKey, nil
}

func loadOrIssue(cfg *config.Config, authority *ca.CA, logger *slog.Logger) (serverCert, serverKey, clientCert, clientKey []byte, err error) {
	if cfg.TLS.PersistPath != "" {
		sc := filepath.Join(cfg.TLS.PersistPath, "server.crt")
		sk := filepath.Join(cfg.TLS.PersistPath, "server.key")
		cc := filepath.Join(cfg.TLS.PersistPath, "client.crt")
		ck := filepath.Join(cfg.TLS.PersistPath, "client.key")

		if fileExists(sc) && fileExists(sk) && fileExists(cc) && fileExists(ck) {
			logger.Info("loading existing certificates from disk")
			serverCert, err = os.ReadFile(sc)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			serverKey, err = os.ReadFile(sk)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			clientCert, err = os.ReadFile(cc)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			clientKey, err = os.ReadFile(ck)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			return serverCert, serverKey, clientCert, clientKey, nil
		}
	}

	logger.Info("issuing new server and client certificates")
	serverCert, serverKey, err = authority.IssueCert("server", "mtls-sandbox-server", cfg.Hostnames)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("issuing server cert: %w", err)
	}
	clientCert, clientKey, err = authority.IssueCert("client", "mtls-sandbox-client", nil)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("issuing client cert: %w", err)
	}
	return serverCert, serverKey, clientCert, clientKey, nil
}

func setupLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	w := os.Stdout
	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot open log file %s: %v, falling back to stdout\n", cfg.Log.File, err)
		} else {
			w = f
		}
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Log.Format == "text" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	return slog.New(handler)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
