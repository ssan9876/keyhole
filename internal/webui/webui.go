// Package webui embeds the built web application and serves it beside the API.
//
// Same origin, deliberately: the CSP in internal/httpapi/middleware.go is
// "default-src 'self'" with no external hosts, and serving the app from
// anywhere else would require loosening it.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// all: is required — without it the pattern skips files beginning with "_" or
// ".", and Vite emits neither today but a plugin could tomorrow.
//
//go:embed all:dist
var embedded embed.FS

const (
	indexPath       = "index.html"
	placeholderPath = "placeholder.html"
)

func dist() (fs.FS, error) { return fs.Sub(embedded, "dist") }

// Built reports whether a real build is embedded rather than the placeholder.
// The release workflow asserts on this so a binary that would serve the
// placeholder never reaches a release page.
func Built() bool {
	files, err := dist()
	if err != nil {
		return false
	}
	_, err = fs.Stat(files, indexPath)
	return err == nil
}

// Handler serves the embedded application.
//
// Two rules, and the difference between them matters:
//
//   - A path under /assets/ is a real file or it is a 404. Falling back to the
//     index there would answer a request for a missing bundle with HTML and a
//     200, which the browser reports as a syntax error in an unrelated file.
//   - Any other unmatched GET returns the index, because the client owns its
//     routes. /enroll/<token> is the first URL a new user opens and there is no
//     file behind it.
//
// If the binary was built without running the web app's build, dist holds
// only placeholder.html and there is no index.html to fall back to. In that
// case the index route serves the placeholder instead, so an operator who
// built wrong gets an explanation rather than a bare 404.
func Handler() (http.Handler, error) {
	files, err := dist()
	if err != nil {
		return nil, err
	}
	server := http.FileServer(http.FS(files))
	built := Built()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = indexPath
		}

		if _, statErr := fs.Stat(files, name); statErr != nil {
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				http.NotFound(w, r)
				return
			}
			name = indexPath
			r = r.Clone(r.Context())
			// "/", not "/index.html": http.FileServer special-cases any request
			// path ending in "/index.html" and 301-redirects it to "./" rather
			// than serving it, so setting the literal index path here would turn
			// every client route into a redirect instead of a 200.
			r.URL.Path = "/"
		}

		if name == indexPath && !built {
			name = placeholderPath
			r = r.Clone(r.Context())
			r.URL.Path = "/" + placeholderPath
		}

		// The manifest's own MIME type, set before ServeContent runs: Go's
		// http.FileServer has no built-in type for .webmanifest, so it would
		// content-sniff the JSON body to text/plain, which browsers warn on.
		// http.ServeContent only sniffs when Content-Type is unset, so setting
		// it here wins.
		if strings.HasSuffix(name, ".webmanifest") {
			w.Header().Set("Content-Type", "application/manifest+json")
		}

		// Overwrites the blanket no-store from securityHeaders, which runs
		// before this handler and has not flushed yet. Vite puts a content hash
		// in every asset filename, so those are immutable; the index names them
		// and must never be cached, or a browser pins itself to an old build.
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		server.ServeHTTP(w, r)
	}), nil
}
