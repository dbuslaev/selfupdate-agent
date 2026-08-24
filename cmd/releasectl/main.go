// Command releasectl is the build-side half of the scheme: it mints the signing
// keypair and produces the signed manifest that clients poll.
//
// It is separate from the update server on purpose, and that separation is the
// central security property of the design. The server only serves bytes; it
// never holds the signing key and cannot mint a release. A full compromise of
// the serving infrastructure lets an attacker withhold updates and serve
// garbage that fails verification, but not ship code.
//
// The file-backed key here is the shape of the thing, not the production
// posture. In production this runs in CI with the key in a KMS or an HSM; the
// signing call is small and synchronous precisely so that swap is contained.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
	"github.com/dbuslaev/selfupdate-agent/internal/manifest"
	"github.com/dbuslaev/selfupdate-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasectl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  releasectl keygen -out PREFIX
  releasectl sign   -key KEY -version V -dir DIR [-rollout N] [-min-supported V]
                    [-next-check SECONDS] [-notes URL]
                    [-requires-reinstall -installer-url URL]
  releasectl verify -pub PUB -manifest FILE
`)
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "release", "output prefix")
	fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// 0600 on the private key. It is the single point of trust for the entire
	// fleet: whoever holds it can execute code on every installed client.
	if err := os.WriteFile(*out+".key", []byte(encode(priv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(encode(pub)), 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %s.key (keep secret) and %s.pub\n", *out, *out)
	fmt.Printf("key_id %s\n", manifest.KeyID(pub))
	return nil
}

type signOptions struct {
	keyPath      string
	version      string
	dir          string
	out          string
	rollout      int
	minSupported string
	nextCheck    int
	notes        string
	downgrade    bool
	reinstall    bool
	installerURL string
}

func sign(args []string) error {
	var o signOptions
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	fs.StringVar(&o.keyPath, "key", "release.key", "private key file")
	fs.StringVar(&o.version, "version", "", "version being released, e.g. 1.2.3")
	fs.StringVar(&o.dir, "dir", "dist", "directory of artifacts named agent-app_GOOS_GOARCH")
	fs.StringVar(&o.out, "out", "", "output path (default DIR/manifest.json)")
	fs.IntVar(&o.rollout, "rollout", 100, "percentage of the fleet offered this release")
	fs.StringVar(&o.minSupported, "min-supported", "", "oldest version allowed to keep running at all")
	fs.IntVar(&o.nextCheck, "next-check", 0, "requested client poll interval, in seconds")
	fs.StringVar(&o.notes, "notes", "", "release notes URL")
	fs.BoolVar(&o.downgrade, "allow-downgrade", false, "permit newer clients to move back to this release")
	fs.BoolVar(&o.reinstall, "requires-reinstall", false, "this release cannot be installed by the agent; clients must run a new installer")
	fs.StringVar(&o.installerURL, "installer-url", "", "where to obtain the installer (required with -requires-reinstall)")
	fs.Parse(args)

	if o.version == "" {
		return errors.New("-version is required")
	}
	if !version.Valid(o.version) {
		return fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", o.version)
	}

	priv, err := loadPrivateKey(o.keyPath)
	if err != nil {
		return err
	}
	artifacts, err := collectArtifacts(o.dir)
	if err != nil {
		return err
	}

	m := &manifest.Manifest{
		Version:             o.version,
		Released:            time.Now().UTC().Truncate(time.Second),
		Artifacts:           artifacts,
		Rollout:             o.rollout,
		MinSupportedVersion: o.minSupported,
		AllowDowngrade:      o.downgrade,
		RequiresReinstall:   o.reinstall,
		InstallerURL:        o.installerURL,
		NextCheckSeconds:    o.nextCheck,
		Notes:               o.notes,
	}

	env, err := manifest.Sign(m, priv)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	dest := o.out
	if dest == "" {
		dest = filepath.Join(o.dir, "manifest.json")
	}
	if err := os.WriteFile(dest, append(body, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Printf("signed %s as %s (rollout %d%%, key_id %s)\n", dest, o.version, o.rollout, env.KeyID)
	if o.reinstall {
		fmt.Printf("NOTE: clients will NOT self-update to this release; they will be told to install from %s\n", o.installerURL)
	}
	return nil
}

// verify is the pre-publish check: it proves a manifest validates against the
// public key that clients actually carry, before it reaches any of them.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "release.pub", "public key file")
	path := fs.String("manifest", "dist/manifest.json", "signed manifest")
	fs.Parse(args)

	pub, err := loadPublicKey(*pubPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var env manifest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	m, err := manifest.Verify(&env, []ed25519.PublicKey{pub})
	if err != nil {
		return err
	}

	fmt.Printf("ok: %s, %d artifacts, rollout %d%%\n", m.Version, len(m.Artifacts), m.Rollout)
	return nil
}

// collectArtifacts scans a build directory for files named
// agent-app_GOOS_GOARCH, hashing each one.
//
// Encoding the platform in the filename means the release step does not have to
// be told what was just built, and a missing platform is obvious in a directory
// listing rather than discovered by a client that finds no artifact for itself.
func collectArtifacts(dir string) ([]manifest.Artifact, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var artifacts []manifest.Artifact
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		goos, goarch, ok := parseArtifactName(entry.Name())
		if !ok {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		digest, size, err := fsutil.SHA256File(path)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, manifest.Artifact{
			OS:     goos,
			Arch:   goarch,
			URL:    "artifacts/" + entry.Name(),
			SHA256: digest,
			Size:   size,
		})
		fmt.Printf("  %-28s %s/%-8s %9d bytes  %s\n", entry.Name(), goos, goarch, size, digest[:16])
	}
	if len(artifacts) == 0 {
		return nil, fmt.Errorf("no artifacts named agent-app_GOOS_GOARCH found in %s", dir)
	}
	return artifacts, nil
}

func parseArtifactName(name string) (goos, goarch string, ok bool) {
	base := strings.TrimSuffix(name, ".exe")
	parts := strings.Split(base, "_")
	if len(parts) != 3 || parts[0] != "agent-app" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := decodeFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := decodeFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func decodeFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return raw, nil
}

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
