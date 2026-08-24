package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateLoadAndSign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	created, pub, err := Create(path, "install-1")
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := Load(path)
	if err != nil || !found {
		t.Fatalf("Load = %v, found=%v", err, found)
	}
	if loaded.InstallID != created.InstallID || loaded.PrivateKey != created.PrivateKey {
		t.Fatal("the loaded identity does not match the created one")
	}

	signer, err := NewSigner(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey(), pub) {
		t.Error("the signer derived a different public key than Create returned")
	}
}

// The private key is the one thing on disk that identifies this install to the
// fleet API, and the residual risk of storing it in a file is local read
// access. Narrow permissions are the mitigation.
func TestIdentityFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if _, _, err := Create(path, "install-1"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("identity file mode = %o, want 0600", got)
	}
}

func TestLoadReportsAbsentAndBrokenDifferently(t *testing.T) {
	dir := t.TempDir()

	if _, found, err := Load(filepath.Join(dir, "missing.json")); found || err != nil {
		t.Errorf("absent identity: found=%v err=%v, want false and nil", found, err)
	}

	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte(`{"install_id":"x"}`), 0o600)
	if _, found, err := Load(broken); found || err == nil {
		t.Errorf("incomplete identity: found=%v err=%v, want false and an error", found, err)
	}
}

func TestSignRequestProducesAVerifiableSignature(t *testing.T) {
	signer, pub := newTestSigner(t)
	body := []byte(`{"events":[]}`)

	req, err := http.NewRequest(http.MethodPost, "https://fleet.example.com/v1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	for _, header := range []string{HeaderInstallID, HeaderTimestamp, HeaderNonce, HeaderSignature} {
		if req.Header.Get(header) == "" {
			t.Errorf("%s was not set", header)
		}
	}

	signed := SigningString(req.Method, req.URL.Path,
		req.Header.Get(HeaderInstallID), req.Header.Get(HeaderTimestamp),
		req.Header.Get(HeaderNonce), body)

	if !ed25519.Verify(pub, signed, decode(t, req.Header.Get(HeaderSignature))) {
		t.Fatal("the signature does not verify")
	}
}

// Each component is in the signing string for a reason, so each is tested:
// altering any of them must invalidate the signature. Without the path, a
// signature could be lifted onto a different endpoint; without the body digest,
// the payload could be swapped; without the nonce or timestamp, either could be
// rewritten to extend a replay window.
func TestSignatureCoversEveryComponent(t *testing.T) {
	signer, pub := newTestSigner(t)
	body := []byte(`{"events":[]}`)

	req, _ := http.NewRequest(http.MethodPost, "https://fleet.example.com/v1/events", bytes.NewReader(body))
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}
	sig := decode(t, req.Header.Get(HeaderSignature))

	base := [6]string{
		req.Method, req.URL.Path,
		req.Header.Get(HeaderInstallID), req.Header.Get(HeaderTimestamp), req.Header.Get(HeaderNonce), "",
	}

	tampered := map[string]func() []byte{
		"method": func() []byte {
			return SigningString("GET", base[1], base[2], base[3], base[4], body)
		},
		"path": func() []byte {
			return SigningString(base[0], "/v1/admin", base[2], base[3], base[4], body)
		},
		"install id": func() []byte {
			return SigningString(base[0], base[1], "other-install", base[3], base[4], body)
		},
		"timestamp": func() []byte {
			return SigningString(base[0], base[1], base[2], "0", base[4], body)
		},
		"nonce": func() []byte {
			return SigningString(base[0], base[1], base[2], base[3], "reused", body)
		},
		"body": func() []byte {
			return SigningString(base[0], base[1], base[2], base[3], base[4], []byte(`{"events":[{"kind":"forged"}]}`))
		},
	}

	for name, build := range tampered {
		if ed25519.Verify(pub, build(), sig) {
			t.Errorf("the signature still verified after altering the %s", name)
		}
	}
}

func TestNewSignerRejectsAMalformedKey(t *testing.T) {
	for _, key := range []string{"", "not-base64!", "c2hvcnQ="} {
		if _, err := NewSigner(&Identity{InstallID: "x", PrivateKey: key}); err == nil {
			t.Errorf("NewSigner accepted a malformed key %q", key)
		}
	}
}

func newTestSigner(t *testing.T) (*Signer, ed25519.PublicKey) {
	t.Helper()
	id, pub, err := Create(filepath.Join(t.TempDir(), "identity.json"), "install-under-test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(id)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pub
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
