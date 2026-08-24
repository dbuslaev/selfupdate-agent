// Command updateserver serves the release channel and provides a reference
// implementation of the fleet API.
//
// The two halves are very different in kind, and keeping that visible is the
// point of putting them in one place:
//
//   - The release channel is static content. It holds no secret and needs no
//     authority, because the manifest is signed offline and every artifact is
//     pinned by digest. In production this is an object store behind a CDN, not
//     a process.
//   - The fleet API is a real service that verifies client signatures and
//     records what the fleet is doing. In production it lives in its own
//     repository with a real datastore. What is here is the contract, written
//     out so the whole loop can be exercised on one machine.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	dir := flag.String("dir", "dist", "directory holding manifest.json and the artifacts")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("component", "updateserver")

	mux := http.NewServeMux()
	registerChannel(mux, *dir, log)
	registerFleetAPI(mux, log)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           logRequests(log, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Info("serving", "addr", *addr, "dir", *dir)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(rec, r)

		log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"agent", r.UserAgent(),
			"dur", time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
