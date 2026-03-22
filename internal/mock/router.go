package mock

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Router matches incoming requests against compiled mock routes.
// If no route matches, it delegates to the next handler.
type Router struct {
	routes []compiledRoute
	next   http.Handler
}

// SetNext sets the fallthrough handler for unmatched requests.
func (rt *Router) SetNext(next http.Handler) {
	rt.next = next
}

// NewRouter compiles the routes from cfg and creates a Router that falls
// through to next when no mock route matches.
func NewRouter(cfg *MockConfig, next http.Handler) (*Router, error) {
	routes := make([]compiledRoute, 0, len(cfg.Routes))

	for i, r := range cfg.Routes {
		cr := compiledRoute{
			method:  r.Method,
			status:  r.Response.Status,
			body:    r.Response.Body,
			headers: r.Response.Headers,
		}

		// Parse path segments.
		cr.segments = parsePath(r.Path)

		// Parse delay.
		if r.Response.Delay != "" {
			d, err := time.ParseDuration(r.Response.Delay)
			if err != nil {
				return nil, fmt.Errorf("route %d (%s): invalid delay %q: %w", i, r.Path, r.Response.Delay, err)
			}
			cr.delay = d
		}

		routes = append(routes, cr)
	}

	return &Router{routes: routes, next: next}, nil
}

func parsePath(path string) []segment {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	segs := make([]segment, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, ":") {
			segs = append(segs, segment{value: p[1:], param: true})
		} else {
			segs = append(segs, segment{value: p})
		}
	}
	return segs
}

// ServeHTTP implements http.Handler. It tries to match the request against
// mock routes and serves the configured response. If no route matches, it
// delegates to the next handler.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, params := rt.match(r.Method, r.URL.Path)
	if route == nil {
		rt.next.ServeHTTP(w, r)
		return
	}

	if route.delay > 0 {
		time.Sleep(route.delay)
	}

	for k, v := range route.headers {
		w.Header().Set(k, expandTemplates(v, params))
	}

	w.WriteHeader(route.status)
	if route.body != "" {
		fmt.Fprint(w, expandTemplates(route.body, params))
	}
}

func (rt *Router) match(method, path string) (*compiledRoute, map[string]string) {
	reqSegs := parsePath(path)

	for i := range rt.routes {
		cr := &rt.routes[i]
		if cr.method != method {
			continue
		}
		if len(cr.segments) != len(reqSegs) {
			continue
		}

		params := make(map[string]string)
		matched := true
		for j, seg := range cr.segments {
			if seg.param {
				params[seg.value] = reqSegs[j].value
			} else if seg.value != reqSegs[j].value {
				matched = false
				break
			}
		}

		if matched {
			return cr, params
		}
	}

	return nil, nil
}

// expandTemplates replaces {{uuid}}, {{timestamp}}, and {{param.X}} placeholders.
func expandTemplates(s string, params map[string]string) string {
	s = strings.ReplaceAll(s, "{{uuid}}", generateUUID())
	s = strings.ReplaceAll(s, "{{timestamp}}", time.Now().Format(time.RFC3339))
	for k, v := range params {
		s = strings.ReplaceAll(s, "{{param."+k+"}}", v)
	}
	return s
}

// generateUUID produces a v4 UUID using crypto/rand, avoiding external dependencies.
func generateUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
