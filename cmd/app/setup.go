package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/events"
	"github.com/dbuslaev/selfupdate-agent/internal/identity"
	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
	"github.com/dbuslaev/selfupdate-agent/internal/updater"
	"github.com/dbuslaev/selfupdate-agent/internal/version"
)

// releaseKeys is a comma-separated list of base64 Ed25519 public keys permitted
// to sign releases, injected at build time:
//
//	-ldflags "-X main.releaseKeys=$(cat release.pub)"
//
// It is a list rather than a single key because that is what makes rotation
// possible: ship a build trusting {old, new}, wait for the fleet to converge,
// then sign with the new key and drop the old one in the release after.
//
// Empty disables updating outright rather than falling back to something
// weaker. A build with no key must not be updatable by anyone.
var releaseKeys string

// newUpdater wires the updater, or returns nil when updating is not configured.
func newUpdater(log *slog.Logger, paths layout.Layout, eventLog *events.Log, opts options) (*updater.Updater, error) {
	if opts.manifestURL == "" || releaseKeys == "" {
		return nil, nil
	}
	keys, err := parseReleaseKeys(releaseKeys)
	if err != nil {
		return nil, err
	}

	return updater.New(updater.Config{
		Layout:      paths,
		ManifestURL: opts.manifestURL,
		TrustedKeys: keys,
		Version:     version.Version,
		Interval:    opts.interval,
		Logger:      log,
		Events:      eventLog,
		Reporter:    newReporter(log, paths, opts.reportURL),
		Store:       state.NewStore(paths.StateFile()),

		// A real program gates this on in-flight work: an open transaction, an
		// upload in progress, an active verification session. Returning false
		// only defers to the next poll, so it is cheap to be conservative.
		CanUpdate: func() bool { return true },
	})
}

// newReporter builds the events reporter, or returns nil when this install has
// no identity or no endpoint. An unenrolled install still records events
// locally for `--status`; it simply does not ship them anywhere.
func newReporter(log *slog.Logger, paths layout.Layout, endpoint string) events.Reporter {
	if endpoint == "" {
		return nil
	}
	id, found, err := identity.Load(paths.IdentityFile())
	if err != nil || !found {
		log.Warn("no usable identity; events will be recorded locally only", "error", err)
		return nil
	}
	signer, err := identity.NewSigner(id)
	if err != nil {
		log.Warn("unusable identity; events will be recorded locally only", "error", err)
		return nil
	}
	return events.NewHTTPReporter(endpoint, signer, 30*time.Second)
}

// parseReleaseKeys decodes the compiled-in trusted keys.
func parseReleaseKeys(encoded string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, field := range strings.Split(encoded, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(field)
		if err != nil {
			return nil, fmt.Errorf("compiled-in release key is not valid base64: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("compiled-in release key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable release keys were compiled into this build")
	}
	return keys, nil
}
