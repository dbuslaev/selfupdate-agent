package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testManifest() *Manifest {
	return &Manifest{
		Version:  "1.2.3",
		Released: time.Now().UTC().Truncate(time.Second),
		Rollout:  100,
		Artifacts: []Artifact{{
			OS:     "linux",
			Arch:   "amd64",
			URL:    "artifacts/agent-app_linux_amd64",
			SHA256: strings.Repeat("ab", 32),
			Size:   1024,
		}},
	}
}

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// tamper rewrites the signed bytes inside an envelope without touching the
// signature, standing in for a server that serves a doctored manifest.
func tamper(t *testing.T, env *Envelope, old, new string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(env.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	env.Manifest = base64.StdEncoding.EncodeToString(
		[]byte(strings.Replace(string(raw), old, new, 1)))
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)

	env, err := Sign(testManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyID != KeyID(pub) {
		t.Errorf("envelope key_id = %q, want %q", env.KeyID, KeyID(pub))
	}

	m, err := Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.2.3" {
		t.Errorf("version = %q", m.Version)
	}
}

// This is the property the entire trust model rests on, so it is asserted
// directly rather than by inference.
func TestVerifyRejectsTamperedVersion(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Sign(testManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}

	tamper(t, env, `"1.2.3"`, `"9.9.9"`)

	if _, err := Verify(env, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("Verify accepted a tampered manifest")
	}
}

// Substituting an artifact digest is the attack the signature exists to stop:
// the serving infrastructure is untrusted, so only the signature keeps it from
// pointing clients at a binary of its own choosing.
func TestVerifyRejectsSubstitutedArtifactDigest(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Sign(testManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}

	tamper(t, env, strings.Repeat("ab", 32), strings.Repeat("cd", 32))

	if _, err := Verify(env, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("Verify accepted a manifest with a substituted artifact digest")
	}
}

func TestVerifyReportsUntrustedKeyDistinctly(t *testing.T) {
	_, priv := mustKeypair(t)
	otherPub, _ := mustKeypair(t)

	env, err := Sign(testManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Verify(env, []ed25519.PublicKey{otherPub})
	if !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("err = %v, want ErrUntrustedKey", err)
	}
}

// Carrying several trusted keys is the mechanism for rotation, so a client
// holding both the old and new key must accept a manifest signed by either.
func TestVerifyAcceptsAnyTrustedKey(t *testing.T) {
	oldPub, _ := mustKeypair(t)
	newPub, newPriv := mustKeypair(t)

	env, err := Sign(testManifest(), newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, []ed25519.PublicKey{oldPub, newPub}); err != nil {
		t.Fatalf("Verify with a rotated key set: %v", err)
	}
}

func TestVerifyRejectsEmptyKeySet(t *testing.T) {
	_, priv := mustKeypair(t)
	env, _ := Sign(testManifest(), priv)

	if _, err := Verify(env, nil); err == nil {
		t.Fatal("Verify accepted a manifest with no trusted keys")
	}
}

// Regression. Carrying the manifest as a nested json.RawMessage looks tidier
// and silently breaks every signature: encoding/json re-indents embedded raw
// messages, so the client verifies different bytes than were signed.
func TestEnvelopeSurvivesIndentedReEncoding(t *testing.T) {
	pub, priv := mustKeypair(t)
	env, err := Sign(testManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}

	wire, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var received Envelope
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(&received, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("verify after an indented round trip: %v", err)
	}
}

func TestValidateRejectsUnusableManifests(t *testing.T) {
	_, priv := mustKeypair(t)

	cases := map[string]func(*Manifest){
		"no version":    func(m *Manifest) { m.Version = "" },
		"no artifacts":  func(m *Manifest) { m.Artifacts = nil },
		"rollout > 100": func(m *Manifest) { m.Rollout = 101 },
		"rollout < 0":   func(m *Manifest) { m.Rollout = -1 },
		"short digest":  func(m *Manifest) { m.Artifacts[0].SHA256 = "abcd" },
		"non-hex":       func(m *Manifest) { m.Artifacts[0].SHA256 = strings.Repeat("zz", 32) },
		"no url":        func(m *Manifest) { m.Artifacts[0].URL = "" },
		"no size":       func(m *Manifest) { m.Artifacts[0].Size = 0 },
		"no os":         func(m *Manifest) { m.Artifacts[0].OS = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testManifest()
			mutate(m)
			if _, err := Sign(m, priv); err == nil {
				t.Errorf("Sign accepted an invalid manifest (%s)", name)
			}
		})
	}
}

// A hostile or mistaken next_check_seconds must not be able to turn the fleet
// into a tight polling loop against the channel.
func TestNextCheckIsClamped(t *testing.T) {
	const (
		fallback = 15 * time.Minute
		low      = 30 * time.Second
		high     = 24 * time.Hour
	)
	cases := []struct {
		seconds int
		want    time.Duration
	}{
		{0, fallback},          // unset
		{-1, fallback},         // nonsense
		{1, low},               // clamped up
		{300, 5 * time.Minute}, // honoured
		{1 << 30, high},        // clamped down
	}

	for _, c := range cases {
		m := &Manifest{NextCheckSeconds: c.seconds}
		if got := m.NextCheck(fallback, low, high); got != c.want {
			t.Errorf("NextCheck(%d) = %v, want %v", c.seconds, got, c.want)
		}
	}
}

func TestArtifactLookup(t *testing.T) {
	m := testManifest()
	if _, ok := m.Artifact("linux", "amd64"); !ok {
		t.Error("expected a linux/amd64 artifact")
	}
	if _, ok := m.Artifact("windows", "amd64"); ok {
		t.Error("did not expect a windows/amd64 artifact")
	}
}

// A release nobody can install, that does not say where the installer is,
// strands every client that reaches it.
func TestReinstallRequiresAnInstallerURL(t *testing.T) {
	_, priv := mustKeypair(t)

	m := testManifest()
	m.RequiresReinstall = true
	if _, err := Sign(m, priv); err == nil {
		t.Fatal("Sign accepted a reinstall release with no installer_url")
	}

	m.InstallerURL = "https://example.com/install"
	if _, err := Sign(m, priv); err != nil {
		t.Fatalf("Sign rejected a well-formed reinstall release: %v", err)
	}
}
