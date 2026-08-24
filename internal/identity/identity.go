// Package identity gives an installation a stable, verifiable identity for
// talking to the fleet API.
//
// # What this does and does not protect
//
// The keypair authenticates the client to the server. That gets trustworthy
// telemetry, per-install rollout targeting, and the ability to revoke a single
// compromised install. It does not protect the update path: the direction that
// matters there is server-to-client, and no amount of request signing helps if
// the server is the thing that is compromised. That is what the offline-signed
// manifest is for, and neither substitutes for the other.
//
// The private key is generated on the client and never leaves it. The server
// stores only public keys, so a breach of the fleet database leaks nothing that
// can impersonate an install.
//
// # Why a file rather than the OS keystore
//
// The key protects transport identity, not code integrity — code integrity is
// already covered by the manifest signature. A stolen key lets an attacker
// impersonate one install to the API, which is bad and revocable rather than
// catastrophic. Against that, an OS keystore costs three separate integrations
// (Keychain, DPAPI, kernel keyring), cgo on macOS, per-binary access prompts,
// and awkward behaviour on machines with no logged-in user — which is most of a
// fleet of background agents. So: a 0600 file in the agent's own data
// directory, with the residual risk noted rather than hidden.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// Headers carrying the signature material.
const (
	HeaderInstallID = "X-Install-Id"
	HeaderTimestamp = "X-Timestamp"
	HeaderNonce     = "X-Nonce"
	HeaderSignature = "X-Signature"
)

// MaxClockSkew is how far a request timestamp may be from the server's clock.
// It bounds replay, but a nonce is still required: within the window a captured
// request would otherwise be replayable. Five minutes rather than one, because
// a client with a drifting RTC should report late telemetry, not be locked out.
const MaxClockSkew = 5 * time.Minute

// Identity is an installation's credentials.
type Identity struct {
	InstallID  string `json:"install_id"`
	PrivateKey string `json:"private_key"` // base64 Ed25519 seed
}

// Load reads the identity file, reporting whether one exists.
func Load(path string) (*Identity, bool, error) {
	raw, found, err := fsutil.ReadJSONFile(path)
	if err != nil || !found {
		return nil, false, err
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, false, fmt.Errorf("parse identity file: %w", err)
	}
	if id.InstallID == "" || id.PrivateKey == "" {
		return nil, false, fmt.Errorf("identity file %s is incomplete", path)
	}
	return &id, true, nil
}

// Create generates a keypair and writes the identity. installID comes from
// enrollment; an unenrolled install passes a locally generated one.
func Create(path, installID string) (*Identity, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}
	id := &Identity{
		InstallID:  installID,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
	}
	if err := id.Save(path); err != nil {
		return nil, nil, err
	}
	return id, pub, nil
}

// Save writes the identity with owner-only permissions.
func (i *Identity) Save(path string) error {
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Signer produces signed requests for one identity.
type Signer struct {
	installID string
	key       ed25519.PrivateKey
}

// NewSigner builds a signer from a stored identity.
func NewSigner(id *Identity) (*Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return &Signer{installID: id.InstallID, key: ed25519.NewKeyFromSeed(seed)}, nil
}

// InstallID returns the identity this signer speaks for.
func (s *Signer) InstallID() string { return s.installID }

// PublicKey returns the verifying half, for enrollment.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// SignRequest attaches the identity headers and a signature.
func (s *Signer) SignRequest(req *http.Request, body []byte) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)

	req.Header.Set(HeaderInstallID, s.installID)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(
		ed25519.Sign(s.key, SigningString(req.Method, req.URL.Path, s.installID, timestamp, nonce, body)),
	))
	return nil
}

// SigningString builds the canonical bytes that both sides sign and verify.
//
// Method and path are included so a signature cannot be lifted onto a different
// endpoint. The body digest is included so the payload cannot be swapped. The
// nonce and timestamp are included so neither can be altered to extend a replay
// window. Fields are newline-separated and fixed in order, which is enough of a
// canonical form given that none of them may contain a newline.
func SigningString(method, path, installID, timestamp, nonce string, body []byte) []byte {
	return []byte(strings.Join([]string{
		method,
		path,
		installID,
		timestamp,
		nonce,
		fsutil.SHA256Bytes(body),
	}, "\n"))
}

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
