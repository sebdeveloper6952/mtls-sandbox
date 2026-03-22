package mock

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRoutes(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "routes.yaml")
	os.WriteFile(yamlPath, []byte(`
routes:
  - path: /api/test
    method: GET
    response:
      status: 200
      body: '{"ok": true}'
      headers:
        Content-Type: application/json
  - path: /api/items/:id
    method: POST
    response:
      status: 201
      body: created
`), 0644)

	cfg, err := LoadRoutes(yamlPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.Routes))
	}

	if cfg.Routes[0].Path != "/api/test" {
		t.Errorf("expected /api/test, got %s", cfg.Routes[0].Path)
	}
	if cfg.Routes[1].Method != "POST" {
		t.Errorf("expected POST, got %s", cfg.Routes[1].Method)
	}
}

func TestLoadRoutesBodyFile(t *testing.T) {
	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "response.json")
	os.WriteFile(bodyPath, []byte(`{"from_file": true}`), 0644)

	yamlPath := filepath.Join(dir, "routes.yaml")
	os.WriteFile(yamlPath, []byte(`
routes:
  - path: /api/test
    method: GET
    response:
      status: 200
      body_file: response.json
`), 0644)

	cfg, err := LoadRoutes(yamlPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Routes[0].Response.Body != `{"from_file": true}` {
		t.Errorf("expected body from file, got %s", cfg.Routes[0].Response.Body)
	}
	if cfg.Routes[0].Response.BodyFile != "" {
		t.Error("expected body_file to be cleared after resolution")
	}
}

func TestLoadRoutesMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "resp.json"), []byte(`{}`), 0644)
	yamlPath := filepath.Join(dir, "routes.yaml")
	os.WriteFile(yamlPath, []byte(`
routes:
  - path: /api/test
    method: GET
    response:
      status: 200
      body: inline
      body_file: resp.json
`), 0644)

	_, err := LoadRoutes(yamlPath)
	if err == nil {
		t.Error("expected error for body + body_file")
	}
}

func TestLoadRoutesInvalidMethod(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "routes.yaml")
	os.WriteFile(yamlPath, []byte(`
routes:
  - path: /test
    method: INVALID
    response:
      status: 200
`), 0644)

	_, err := LoadRoutes(yamlPath)
	if err == nil {
		t.Error("expected error for invalid method")
	}
}

func TestRouterExactMatch(t *testing.T) {
	cfg := &MockConfig{
		Routes: []Route{
			{
				Path: "/api/test", Method: "GET",
				Response: Response{Status: 200, Body: "hello"},
			},
		},
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	})

	router, err := NewRouter(cfg, fallback)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("expected hello, got %s", rec.Body.String())
	}
}

func TestRouterParamMatch(t *testing.T) {
	cfg := &MockConfig{
		Routes: []Route{
			{
				Path: "/api/accounts/:id", Method: "GET",
				Response: Response{
					Status: 200,
					Body:   `{"id": "{{param.id}}"}`,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				},
			},
		},
	}

	router, _ := NewRouter(cfg, http.NotFoundHandler())

	req := httptest.NewRequest("GET", "/api/accounts/abc123", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"abc123"`) {
		t.Errorf("expected param substitution, got %s", body)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type header")
	}
}

func TestRouterMethodFiltering(t *testing.T) {
	cfg := &MockConfig{
		Routes: []Route{
			{Path: "/api/test", Method: "POST", Response: Response{Status: 201, Body: "created"}},
		},
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})

	router, _ := NewRouter(cfg, fallback)

	// GET should not match
	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("expected 404 for wrong method, got %d", rec.Code)
	}

	// POST should match
	req = httptest.NewRequest("POST", "/api/test", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestRouterFallthrough(t *testing.T) {
	cfg := &MockConfig{
		Routes: []Route{
			{Path: "/api/mock", Method: "GET", Response: Response{Status: 200, Body: "mocked"}},
		},
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("original"))
	})

	router, _ := NewRouter(cfg, fallback)

	req := httptest.NewRequest("GET", "/other/path", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "original" {
		t.Errorf("expected fallthrough to original handler, got %s", string(body))
	}
}

func TestTemplateExpansion(t *testing.T) {
	params := map[string]string{"id": "42"}

	result := expandTemplates("id={{param.id}}", params)
	if result != "id=42" {
		t.Errorf("expected id=42, got %s", result)
	}

	result = expandTemplates("uuid={{uuid}}", nil)
	if strings.Contains(result, "{{uuid}}") {
		t.Error("expected uuid to be expanded")
	}
	// UUID format: 8-4-4-4-12 hex chars
	uuid := strings.TrimPrefix(result, "uuid=")
	if len(uuid) != 36 {
		t.Errorf("expected 36-char UUID, got %d chars: %s", len(uuid), uuid)
	}

	result = expandTemplates("ts={{timestamp}}", nil)
	if strings.Contains(result, "{{timestamp}}") {
		t.Error("expected timestamp to be expanded")
	}
}

func TestGenerateUUID(t *testing.T) {
	uuid := generateUUID()
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		t.Errorf("expected 5 parts, got %d: %s", len(parts), uuid)
	}
	// Version nibble should be 4
	if uuid[14] != '4' {
		t.Errorf("expected version 4 at position 14, got %c", uuid[14])
	}
}
