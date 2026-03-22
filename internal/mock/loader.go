package mock

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// validMethods lists the HTTP methods accepted in mock route definitions.
var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// LoadRoutes reads and validates a mock routes YAML file.
// BodyFile paths are resolved relative to the YAML file's directory and their
// contents are read eagerly into Response.Body.
func LoadRoutes(path string) (*MockConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading mock routes file: %w", err)
	}

	var cfg MockConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing mock routes file: %w", err)
	}

	dir := filepath.Dir(path)

	for i := range cfg.Routes {
		r := &cfg.Routes[i]

		if r.Path == "" {
			return nil, fmt.Errorf("route %d: path is required", i)
		}

		r.Method = strings.ToUpper(r.Method)
		if !validMethods[r.Method] {
			return nil, fmt.Errorf("route %d (%s): invalid method %q", i, r.Path, r.Method)
		}

		if r.Response.Status < 100 || r.Response.Status > 599 {
			return nil, fmt.Errorf("route %d (%s): status must be 100-599, got %d", i, r.Path, r.Response.Status)
		}

		if r.Response.Body != "" && r.Response.BodyFile != "" {
			return nil, fmt.Errorf("route %d (%s): body and body_file are mutually exclusive", i, r.Path)
		}

		if r.Response.BodyFile != "" {
			p := r.Response.BodyFile
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			content, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("route %d (%s): reading body_file: %w", i, r.Path, err)
			}
			r.Response.Body = string(content)
			r.Response.BodyFile = "" // clear after resolving
		}
	}

	return &cfg, nil
}
