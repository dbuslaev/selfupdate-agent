package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
)

// A machine that has been switched off comes back on a stale build. Deferring
// the first check to the first tick means it spends that window running a
// version that may already be below min_supported_version, which is exactly the
// condition the floor exists to catch.
func TestRunChecksImmediatelyAtStartup(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		http.Error(w, "no manifest", http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	u, err := New(Config{
		Layout:      layout.Layout{InstallDir: dir, DataDir: dir},
		ManifestURL: srv.URL + "/manifest.json",
		TrustedKeys: trustedKeyForTest(t),
		Version:     "1.0.0",
		// An interval far longer than the test: if the first check waited for a
		// tick, no request would ever arrive.
		Interval: time.Hour,
		Store:    state.NewStore(filepath.Join(dir, "state.json")),
		Logger:   quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = u.Run(ctx)

	if got := polls.Load(); got == 0 {
		t.Fatal("no check was made at startup; the first poll waited for a tick")
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func trustedKeyForTest(t *testing.T) []ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []ed25519.PublicKey{pub}
}
