package mock

import "time"

// MockConfig is the top-level structure of a mock routes YAML file.
type MockConfig struct {
	Routes []Route `yaml:"routes"`
}

// Route defines a single mock API endpoint.
type Route struct {
	Path     string   `yaml:"path"`
	Method   string   `yaml:"method"`
	Response Response `yaml:"response"`
}

// Response defines the mock response for a route.
type Response struct {
	Status   int               `yaml:"status"`
	Body     string            `yaml:"body"`
	BodyFile string            `yaml:"body_file"`
	Headers  map[string]string `yaml:"headers"`
	Delay    string            `yaml:"delay"`
}

// compiledRoute is the internal, pre-processed form of a Route.
type compiledRoute struct {
	segments []segment // parsed path segments
	method   string
	status   int
	body     string            // resolved body content (from Body or BodyFile)
	headers  map[string]string // response headers
	delay    time.Duration
}

// segment is a single path component.
type segment struct {
	value string // literal value or param name (without ':')
	param bool   // true if this is a :param wildcard
}
