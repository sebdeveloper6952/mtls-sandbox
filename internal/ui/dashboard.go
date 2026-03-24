package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:static
var staticFS embed.FS

// Handler returns an http.Handler that serves the embedded dashboard files
// with SPA fallback: unknown paths serve index.html for client-side routing.
func Handler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root always serves index.html.
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Check if the file exists in the embedded FS.
		f, err := sub.Open(path[1:]) // strip leading /
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback: serve index.html for client-side routes.
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
