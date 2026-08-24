package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dbuslaev/selfupdate-agent/internal/manifest"
)

func TestArtifactURLStaysWithinManifestOrigin(t *testing.T) {
	s := NewSource("https://releases.example.com/stable/manifest.json", nil, http.DefaultClient, "test")

	got, err := s.artifactURL(manifest.Artifact{URL: "artifacts/agent-app_linux_amd64"})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://releases.example.com/stable/artifacts/agent-app_linux_amd64"
	if got != want {
		t.Errorf("relative URL resolved to %q, want %q", got, want)
	}

	// A leaked signing key should not also be enough to point the fleet at an
	// arbitrary host.
	for _, bad := range []string{
		"https://evil.example.com/agent-app",
		"http://releases.example.com/agent-app", // scheme downgrade
		"file:///etc/passwd",
	} {
		if _, err := s.artifactURL(manifest.Artifact{URL: bad}); err == nil {
			t.Errorf("artifactURL(%q) was allowed to leave the manifest origin", bad)
		}
	}
}

func TestDownloadVerifiesSizeAndDigest(t *testing.T) {
	payload := []byte("this is a binary, honest")
	sum := sha256.Sum256(payload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	newSource := func() *Source {
		return NewSource(srv.URL+"/manifest.json", nil, srv.Client(), "test")
	}
	goodArtifact := manifest.Artifact{
		URL:    srv.URL + "/artifacts/agent-app",
		SHA256: hex.EncodeToString(sum[:]),
		Size:   int64(len(payload)),
	}

	t.Run("accepts a matching artifact", func(t *testing.T) {
		dir := t.TempDir()

		path, err := newSource().Download(context.Background(), goodArtifact, dir, "agent-app.staged")
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(payload) {
			t.Error("downloaded bytes do not match")
		}
		// Staging beside the eventual target is what keeps the later rename on
		// one filesystem.
		if filepath.Dir(path) != dir {
			t.Errorf("staged into %s, want %s", filepath.Dir(path), dir)
		}
	})

	t.Run("rejects a digest mismatch and leaves nothing behind", func(t *testing.T) {
		dir := t.TempDir()
		bad := goodArtifact
		bad.SHA256 = strings.Repeat("11", 32)

		if _, err := newSource().Download(context.Background(), bad, dir, "agent-app.staged"); err == nil {
			t.Fatal("Download accepted a mismatched digest")
		}
		assertEmpty(t, dir)
	})

	t.Run("rejects a short transfer", func(t *testing.T) {
		dir := t.TempDir()
		bad := goodArtifact
		bad.Size = int64(len(payload)) + 10 // the server will send fewer bytes than promised

		if _, err := newSource().Download(context.Background(), bad, dir, "agent-app.staged"); err == nil {
			t.Fatal("Download accepted a truncated artifact")
		}
		assertEmpty(t, dir)
	})
}

func TestManifestVerificationRejectsUnsignedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"manifest":"e30=","key_id":"deadbeef","signature":"AA=="}`))
	}))
	defer srv.Close()

	s := NewSource(srv.URL+"/manifest.json", nil, srv.Client(), "test")
	if _, err := s.Manifest(context.Background()); err == nil {
		t.Fatal("a manifest was accepted with no trusted keys configured")
	}
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%s was left behind after a failed download", e.Name())
	}
}
