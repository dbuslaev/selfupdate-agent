package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/dbuslaev/selfupdate-agent/internal/manifest"
)

// ErrNotModified means the manifest is unchanged since the last poll.
var ErrNotModified = errors.New("manifest not modified")

// Source fetches releases from a channel: a signed manifest plus artifacts.
//
// The channel is static content. It needs no authentication and holds no
// secret, because the manifest is signed offline and every artifact is pinned
// by digest — which is why this can be an object store behind a CDN rather than
// an application server.
type Source struct {
	manifestURL string
	trustedKeys []ed25519.PublicKey
	client      *http.Client
	userAgent   string

	etag string // cached across polls; losing it costs one small GET
}

// NewSource returns a source for one channel.
func NewSource(manifestURL string, trustedKeys []ed25519.PublicKey, client *http.Client, userAgent string) *Source {
	return &Source{
		manifestURL: manifestURL,
		trustedKeys: trustedKeys,
		client:      client,
		userAgent:   userAgent,
	}
}

// Manifest fetches and verifies the current manifest.
//
// A conditional request keeps the steady state cheap: a fleet polling an
// unchanged manifest costs a 304 rather than a body.
func (s *Source) Manifest(ctx context.Context) (*manifest.Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.manifestURL, nil)
	if err != nil {
		return nil, err
	}
	if s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, ErrNotModified
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("fetch manifest: unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, manifest.MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if len(body) > manifest.MaxSize {
		return nil, fmt.Errorf("manifest exceeds %d bytes", manifest.MaxSize)
	}

	var env manifest.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	m, err := manifest.Verify(&env, s.trustedKeys)
	if err != nil {
		return nil, err
	}

	// Cache the validator only after the body verifies, so a server cannot pin
	// the client to a manifest it rejected.
	s.etag = resp.Header.Get("ETag")
	return m, nil
}

// Download streams an artifact to destDir and returns the path of the file.
//
// The caller passes the directory the binary will eventually live in. Staging
// there rather than in the system temp directory keeps the later rename on one
// filesystem; across a mount boundary it would silently degrade into a copy and
// reopen the torn-write window the design exists to close.
func (s *Source) Download(ctx context.Context, a manifest.Artifact, destDir, destName string) (string, error) {
	src, err := s.artifactURL(a)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download artifact: unexpected status %s", resp.Status)
	}

	path := filepath.Join(destDir, destName)
	if err := writeVerified(path, resp.Body, a); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// writeVerified streams body to path, checking size and digest as it goes, and
// removes nothing on success.
func writeVerified(path string, body io.Reader, a manifest.Artifact) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	// Bound the read at exactly the advertised size. The manifest is signed, so
	// anything longer is corruption or an attempt to fill the disk.
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, digest), io.LimitReader(body, a.Size))
	if err != nil {
		return fmt.Errorf("download artifact: %w", err)
	}
	if n != a.Size {
		return fmt.Errorf("download artifact: received %d bytes, manifest declares %d", n, a.Size)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != a.SHA256 {
		return fmt.Errorf("download artifact: digest %s does not match manifest %s", got, a.SHA256)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync downloaded binary: %w", err)
	}
	return nil
}

// artifactURL resolves a possibly relative artifact URL and refuses to leave
// the manifest's origin.
//
// The manifest is signed, so this is defence in depth rather than the primary
// control. It matters because signing keys do occasionally leak, and this keeps
// a leaked key from being enough to point the fleet at an arbitrary host.
func (s *Source) artifactURL(a manifest.Artifact) (string, error) {
	base, err := url.Parse(s.manifestURL)
	if err != nil {
		return "", fmt.Errorf("parse manifest URL: %w", err)
	}
	ref, err := url.Parse(a.URL)
	if err != nil {
		return "", fmt.Errorf("parse artifact URL: %w", err)
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != base.Scheme || abs.Host != base.Host {
		return "", fmt.Errorf("artifact URL %s is outside the manifest origin %s://%s",
			abs, base.Scheme, base.Host)
	}
	return abs.String(), nil
}

// UserAgent identifies the client to the channel. The access log it produces is
// a crude but genuinely useful version census.
func UserAgent(name, ver string) string {
	return fmt.Sprintf("%s/%s (%s/%s)", name, ver, runtime.GOOS, runtime.GOARCH)
}

func drainAndClose(body io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(body, 64<<10)) // allow connection reuse
	body.Close()
}
