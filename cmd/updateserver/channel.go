package main

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// registerChannel wires the static release channel.
func registerChannel(mux *http.ServeMux, dir string, log *slog.Logger) {
	mux.HandleFunc("/manifest.json", manifestHandler(dir, log))

	// Artifacts are immutable once released — a version is never rebuilt — so
	// they can be cached indefinitely. The manifest is the only thing that ever
	// needs revalidating.
	mux.Handle("/artifacts/", http.StripPrefix("/artifacts/",
		immutable(http.FileServer(http.Dir(dir)))))
}

// manifestHandler serves the signed manifest with a content-derived ETag.
//
// Deriving the validator from the bytes rather than from mtime means a rebuild
// producing an identical manifest does not invalidate every client's cache, and
// re-reading on each request means `releasectl sign` publishes a release
// without a restart — which is what makes the rollout dial useful during an
// incident.
func manifestHandler(dir string, log *slog.Logger) http.HandlerFunc {
	path := filepath.Join(dir, "manifest.json")

	return func(w http.ResponseWriter, r *http.Request) {
		body, err := os.ReadFile(path)
		if err != nil {
			// No manifest is a legitimate state for a fresh channel. Clients
			// treat a non-200 as "nothing to do" and retry.
			log.Warn("manifest unavailable", "path", path, "error", err)
			http.Error(w, "no manifest", http.StatusNotFound)
			return
		}

		etag := `"` + fsutil.SHA256Bytes(body)[:32] + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache") // revalidate, never blind-cache

		if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write(body)
	}
}

func immutable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		next.ServeHTTP(w, r)
	})
}
