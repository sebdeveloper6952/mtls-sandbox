package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode       string      `yaml:"mode"`
	Port       int         `yaml:"port"`
	HealthPort int         `yaml:"health_port"`
	TLS        TLSConfig   `yaml:"tls"`
	Hostnames  []string    `yaml:"hostnames"`
	Log        LogConfig   `yaml:"log"`
	Mock       MockConfig  `yaml:"mock"`
	Store      StoreConfig `yaml:"store"`
}

type MockConfig struct {
	RoutesFile string `yaml:"routes_file"`
}

type StoreConfig struct {
	Capacity int    `yaml:"capacity"`
	LogFile  string `yaml:"log_file"`
}

type TLSConfig struct {
	CACert      string `yaml:"ca_cert"`
	CAKey       string `yaml:"ca_key"`
	ServerCert  string `yaml:"server_cert"`
	ServerKey   string `yaml:"server_key"`
	ClientCert  string `yaml:"client_cert"`
	ClientKey   string `yaml:"client_key"`
	PersistPath string `yaml:"persist_path"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

func Defaults() *Config {
	return &Config{
		Mode:       "strict",
		Port:       8443,
		HealthPort: 8080,
		TLS: TLSConfig{
			PersistPath: "./certs",
		},
		Hostnames: []string{"localhost", "127.0.0.1"},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Store: StoreConfig{
			Capacity: 500,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	switch c.Mode {
	case "strict", "lenient", "inspect":
	default:
		return fmt.Errorf("mode must be strict, lenient, or inspect; got %q", c.Mode)
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535; got %d", c.Port)
	}

	if c.HealthPort <= 0 || c.HealthPort > 65535 {
		return fmt.Errorf("health_port must be between 1 and 65535; got %d", c.HealthPort)
	}

	if c.Port == c.HealthPort {
		return fmt.Errorf("port and health_port must be different; both are %d", c.Port)
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log level must be debug, info, warn, or error; got %q", c.Log.Level)
	}

	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log format must be json or text; got %q", c.Log.Format)
	}

	if c.Store.Capacity <= 0 {
		return fmt.Errorf("store capacity must be positive; got %d", c.Store.Capacity)
	}

	return nil
}

func applyEnvOverrides(cfg *Config) {
	if v, ok := os.LookupEnv("MTLS_MODE"); ok {
		cfg.Mode = v
	}
	if v, ok := os.LookupEnv("MTLS_PORT"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Port = n
		}
	}
	if v, ok := os.LookupEnv("MTLS_HEALTH_PORT"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.HealthPort = n
		}
	}
	if v, ok := os.LookupEnv("MTLS_TLS_CA_CERT"); ok {
		cfg.TLS.CACert = v
	}
	if v, ok := os.LookupEnv("MTLS_TLS_CA_KEY"); ok {
		cfg.TLS.CAKey = v
	}
	if v, ok := os.LookupEnv("MTLS_TLS_SERVER_CERT"); ok {
		cfg.TLS.ServerCert = v
	}
	if v, ok := os.LookupEnv("MTLS_TLS_SERVER_KEY"); ok {
		cfg.TLS.ServerKey = v
	}
	if v, ok := os.LookupEnv("MTLS_TLS_CLIENT_CERT"); ok {
		cfg.TLS.ClientCert = v
	}
	if v, ok := os.LookupEnv("MTLS_TLS_CLIENT_KEY"); ok {
		cfg.TLS.ClientKey = v
	}
	if v, ok := os.LookupEnv("MTLS_TLS_PERSIST_PATH"); ok {
		cfg.TLS.PersistPath = v
	}
	if v, ok := os.LookupEnv("MTLS_HOSTNAMES"); ok {
		cfg.Hostnames = strings.Split(v, ",")
	}
	if v, ok := os.LookupEnv("MTLS_LOG_LEVEL"); ok {
		cfg.Log.Level = v
	}
	if v, ok := os.LookupEnv("MTLS_LOG_FORMAT"); ok {
		cfg.Log.Format = v
	}
	if v, ok := os.LookupEnv("MTLS_LOG_FILE"); ok {
		cfg.Log.File = v
	}
	if v, ok := os.LookupEnv("MTLS_MOCK_ROUTES_FILE"); ok {
		cfg.Mock.RoutesFile = v
	}
	if v, ok := os.LookupEnv("MTLS_STORE_CAPACITY"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Store.Capacity = n
		}
	}
	if v, ok := os.LookupEnv("MTLS_STORE_LOG_FILE"); ok {
		cfg.Store.LogFile = v
	}
}
