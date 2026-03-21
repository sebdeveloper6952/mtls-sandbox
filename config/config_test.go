package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Mode != "strict" {
		t.Errorf("expected mode strict, got %s", cfg.Mode)
	}
	if cfg.Port != 8443 {
		t.Errorf("expected port 8443, got %d", cfg.Port)
	}
	if cfg.HealthPort != 8080 {
		t.Errorf("expected health_port 8080, got %d", cfg.HealthPort)
	}
	if cfg.TLS.PersistPath != "./certs" {
		t.Errorf("expected persist_path ./certs, got %s", cfg.TLS.PersistPath)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("expected log level info, got %s", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("expected log format json, got %s", cfg.Log.Format)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("defaults should be valid: %v", err)
	}
}

func TestLoadFromYAML(t *testing.T) {
	yaml := `
mode: lenient
port: 9443
health_port: 9080
tls:
  persist_path: /tmp/test-certs
hostnames:
  - example.com
log:
  level: debug
  format: text
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Mode != "lenient" {
		t.Errorf("expected mode lenient, got %s", cfg.Mode)
	}
	if cfg.Port != 9443 {
		t.Errorf("expected port 9443, got %d", cfg.Port)
	}
	if cfg.HealthPort != 9080 {
		t.Errorf("expected health_port 9080, got %d", cfg.HealthPort)
	}
	if cfg.TLS.PersistPath != "/tmp/test-certs" {
		t.Errorf("expected persist_path /tmp/test-certs, got %s", cfg.TLS.PersistPath)
	}
	if len(cfg.Hostnames) != 1 || cfg.Hostnames[0] != "example.com" {
		t.Errorf("expected hostnames [example.com], got %v", cfg.Hostnames)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.Log.Level)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "strict" {
		t.Errorf("expected defaults with empty path, got mode %s", cfg.Mode)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("MTLS_MODE", "inspect")
	t.Setenv("MTLS_PORT", "7443")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Mode != "inspect" {
		t.Errorf("expected mode inspect from env, got %s", cfg.Mode)
	}
	if cfg.Port != 7443 {
		t.Errorf("expected port 7443 from env, got %d", cfg.Port)
	}
}

func TestValidateInvalidMode(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestValidateInvalidPort(t *testing.T) {
	cfg := Defaults()
	cfg.Port = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for port 0")
	}
}

func TestValidateSamePort(t *testing.T) {
	cfg := Defaults()
	cfg.Port = 8080
	cfg.HealthPort = 8080
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when port equals health_port")
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Level = "trace"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid log level")
	}
}

func TestValidateInvalidLogFormat(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid log format")
	}
}
