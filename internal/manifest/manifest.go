// Package manifest defines the release manifest and its signature envelope.
//
// # Trust model
//
// The client trusts one thing: an Ed25519 public key compiled into it at build
// time. The manifest is signed with the matching private key, and the manifest
// carries a SHA-256 for every artifact, so authenticity of a downloaded binary
// follows transitively from that one embedded key.
//
// Everything else is untrusted — the update server, the CDN, the network. A
// fully compromised server can withhold an update but cannot ship one, because
// the signing key never exists on serving infrastructure. It lives in CI or a
// KMS and signs at release time. That property is the reason this package
// exists rather than relying on TLS and a checksum.
package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MaxSize bounds how much manifest is read from the network. Verifying a
// signature over unbounded attacker-controlled input is a memory exhaustion bug
// waiting to happen.
const MaxSize = 1 << 20 // 1 MiB

// ErrUntrustedKey means the envelope was signed by a key this build does not
// carry. It is distinct from a failed signature because the two demand
// different responses: one is a rotation mistake, the other is corruption or an
// attack.
var ErrUntrustedKey = errors.New("manifest signed by an untrusted key")

// Artifact is one built binary for one platform.
type Artifact struct {
	OS     string `json:"os"`     // GOOS
	Arch   string `json:"arch"`   // GOARCH
	URL    string `json:"url"`    // absolute, or relative to the manifest URL
	SHA256 string `json:"sha256"` // lowercase hex
	Size   int64  `json:"size"`   // bytes, so the download can be bounded
}

// Manifest describes the release that clients should converge on.
type Manifest struct {
	Version   string     `json:"version"`
	Released  time.Time  `json:"released"`
	Artifacts []Artifact `json:"artifacts"`

	// Rollout is the percentage of the fleet (0-100) offered this release. Each
	// client buckets itself deterministically, so raising the number only adds
	// clients; it never reshuffles them.
	Rollout int `json:"rollout"`

	// MinSupportedVersion is the oldest version allowed to keep running at all.
	// A client below it stops rather than operating indefinitely on a build with
	// a known problem. This is the staleness backstop, and it is the reason a
	// rollback cannot silently pin a client to an old version forever.
	MinSupportedVersion string `json:"min_supported_version,omitempty"`

	// RequiresReinstall marks a release the agent cannot install itself —
	// typically one that changes the shim or the service definition, neither of
	// which the running agent owns. Clients hold where they are, report it, and
	// tell the operator a new installer is needed.
	//
	// This should be close to never. It converts a silent background update
	// into one that needs a download, elevation, and usually a human, so it is
	// the emergency hatch rather than a routine mechanism.
	RequiresReinstall bool `json:"requires_reinstall,omitempty"`

	// InstallerURL is where to obtain that installer. Only meaningful with
	// RequiresReinstall, and carried in the signed manifest so the address a
	// client is sent to cannot be substituted by whatever is serving the bytes.
	InstallerURL string `json:"installer_url,omitempty"`

	// AllowDowngrade permits pulling the fleet back to an older build after a
	// bad release. Without it clients refuse to move backwards, so replaying an
	// old signed manifest cannot reintroduce a fixed bug.
	AllowDowngrade bool `json:"allow_downgrade,omitempty"`

	// NextCheckSeconds lets the server pace the fleet: shorten it during an
	// active rollout, lengthen it when nothing is happening. Because it travels
	// inside the signed manifest, pacing needs no separate API and cannot be
	// manipulated by whatever is serving the bytes.
	NextCheckSeconds int `json:"next_check_seconds,omitempty"`

	// Notes is a URL to human-readable release notes. A URL rather than inline
	// text, so a changelog is not shipped to every client on every poll.
	Notes string `json:"notes,omitempty"`
}

// Envelope is what is actually served.
//
// The signed payload travels base64-encoded rather than as nested JSON. Nesting
// it as a json.RawMessage reads better and is wrong: encoding/json re-indents
// embedded raw messages when the outer document is marshalled with indentation,
// so the bytes a client parses are not the bytes that were signed and every
// signature fails. Base64 makes the payload opaque to the JSON encoder, which
// is the only way to guarantee it round-trips unchanged.
type Envelope struct {
	Manifest  string `json:"manifest"`  // base64 of the signed manifest bytes
	KeyID     string `json:"key_id"`    // which key signed it
	Signature string `json:"signature"` // base64 Ed25519 over the decoded manifest
}

// KeyID is a short stable identifier for a public key.
//
// Carrying it lets a client report "signed by a key I do not have" instead of
// the far less actionable "bad signature", and it is what key rotation hangs
// off: ship a build trusting both keys, wait for the fleet to converge, then
// sign with the new one.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Sign wraps m in a signed envelope.
func Sign(m *Manifest, priv ed25519.PrivateKey) (*Envelope, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("private key has no ed25519 public half")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return &Envelope{
		Manifest:  base64.StdEncoding.EncodeToString(payload),
		KeyID:     KeyID(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}, nil
}

// Verify checks an envelope against the trusted keys and returns the manifest.
// Nothing else in this repository is permitted to parse a manifest.
func Verify(env *Envelope, trusted []ed25519.PublicKey) (*Manifest, error) {
	if len(trusted) == 0 {
		return nil, errors.New("no trusted keys compiled into this build")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Manifest)
	if err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if len(payload) > MaxSize {
		return nil, fmt.Errorf("manifest exceeds %d bytes", MaxSize)
	}

	var sawKey bool
	for _, pub := range trusted {
		if len(pub) != ed25519.PublicKeySize || KeyID(pub) != env.KeyID {
			continue
		}
		sawKey = true
		if !ed25519.Verify(pub, payload, sig) {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("parse manifest: %w", err)
		}
		if err := m.Validate(); err != nil {
			return nil, err
		}
		return &m, nil
	}
	if !sawKey {
		return nil, fmt.Errorf("%w: key_id %q", ErrUntrustedKey, env.KeyID)
	}
	return nil, errors.New("manifest signature verification failed")
}

// Artifact returns the artifact for a platform.
func (m *Manifest) Artifact(goos, goarch string) (Artifact, bool) {
	for _, a := range m.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return Artifact{}, false
}

// NextCheck returns the server's requested poll interval, or fallback when the
// manifest does not express a preference. The result is clamped so a malformed
// or hostile value cannot turn the fleet into a tight polling loop.
func (m *Manifest) NextCheck(fallback, min, max time.Duration) time.Duration {
	if m.NextCheckSeconds <= 0 {
		return fallback
	}
	d := time.Duration(m.NextCheckSeconds) * time.Second
	switch {
	case d < min:
		return min
	case d > max:
		return max
	}
	return d
}

// Validate rejects a manifest that cannot be acted on safely. It runs on both
// the signing and the verifying side, so a malformed release is caught before
// publication rather than by every client.
func (m *Manifest) Validate() error {
	if m.Version == "" {
		return errors.New("manifest has no version")
	}
	if m.Rollout < 0 || m.Rollout > 100 {
		return fmt.Errorf("manifest rollout %d is out of range", m.Rollout)
	}
	if len(m.Artifacts) == 0 {
		return errors.New("manifest has no artifacts")
	}
	for i, a := range m.Artifacts {
		if err := a.validate(); err != nil {
			return fmt.Errorf("artifact %d: %w", i, err)
		}
	}
	// A release nobody can install without an installer, that does not say
	// where the installer is, strands every client that reaches it.
	if m.RequiresReinstall && m.InstallerURL == "" {
		return errors.New("manifest requires a reinstall but gives no installer_url")
	}
	return nil
}

func (a Artifact) validate() error {
	switch {
	case a.OS == "" || a.Arch == "":
		return errors.New("missing os or arch")
	case a.URL == "":
		return errors.New("missing url")
	case a.Size <= 0:
		return errors.New("missing size")
	}
	if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != sha256.Size {
		return fmt.Errorf("sha256 must be %d hex-encoded bytes", sha256.Size)
	}
	return nil
}
