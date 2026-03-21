package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sebdeveloper6952/mtls-sandbox/config"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/ca"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to config YAML file")
	ephemeral := flag.Bool("ephemeral", false, "do not persist generated certificates to disk")
	flag.Parse()

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

	srv, err := server.New(cfg, authority.CertPEM, serverCertPEM, serverKeyPEM, logger)
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

func initCA(cfg *config.Config, logger *slog.Logger) (authority *ca.CA, serverCert, serverKey, clientCert, clientKey []byte, err error) {
	// Case 1: User provided their own CA.
	if cfg.TLS.CACert != "" && cfg.TLS.CAKey != "" {
		logger.Info("loading user-provided CA", "cert", cfg.TLS.CACert, "key", cfg.TLS.CAKey)
		authority, err = ca.LoadCA(cfg.TLS.CACert, cfg.TLS.CAKey)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("loading CA: %w", err)
		}
		serverCert, serverKey, clientCert, clientKey, err = loadOrIssue(cfg, authority, logger)
		return
	}

	// Case 2: Certs exist at persist path.
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

	// Case 3: Generate new CA and certs.
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
	// Try loading existing server/client certs from persist path.
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

	// Issue fresh certs.
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
