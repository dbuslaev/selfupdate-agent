package updater

import (
	"fmt"
	"hash/fnv"
	"runtime"

	"github.com/dbuslaev/selfupdate-agent/internal/manifest"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
	"github.com/dbuslaev/selfupdate-agent/internal/version"
)

// Decision is the outcome of evaluating a manifest against this install.
type Decision struct {
	// Apply is true when the release should be downloaded and staged.
	Apply bool
	// Artifact is the binary for this platform, set when Apply is true.
	Artifact manifest.Artifact
	// Stop is true when this client is too old to keep running.
	Stop bool
	// Reinstall is true when the release exists and applies, but cannot be
	// installed by the agent itself. The client keeps running its current
	// version and surfaces the requirement.
	Reinstall bool
	// InstallerURL is where to obtain the installer, set with Reinstall.
	InstallerURL string
	// Reason explains the decision, phrased for a log line an operator will
	// read while wondering why a client is not moving.
	Reason string
}

// Evaluate decides what to do with a verified manifest.
//
// The checks run cheapest-first and in a fixed order, so the reason reported is
// always the first and most specific one that applies. Every branch produces a
// reason: a client that silently declines to update is the hardest kind to
// debug from the outside.
func Evaluate(m *manifest.Manifest, current string, st *state.State) Decision {
	if !version.Valid(m.Version) {
		return Decision{Reason: fmt.Sprintf("manifest version %q cannot be ordered", m.Version)}
	}

	// The staleness backstop runs before anything else, because a client below
	// the supported floor must stop even if no update is available to it.
	if m.MinSupportedVersion != "" && version.Older(current, m.MinSupportedVersion) {
		return Decision{
			Stop: true,
			Reason: fmt.Sprintf("running %s, below the minimum supported version %s",
				current, m.MinSupportedVersion),
		}
	}

	if st.IsPoisoned(m.Version) {
		// This exact build already failed here. Re-downloading it would produce
		// the same crash, so the client holds where it is and lets the fleet
		// API see the failure it already reported.
		return Decision{Reason: fmt.Sprintf("%s previously failed on this machine", m.Version)}
	}

	switch cmp := version.Compare(m.Version, current); {
	case cmp == 0:
		return Decision{Reason: "already on this version"}
	case cmp < 0 && !m.AllowDowngrade:
		// Refusing to move backwards is what stops a replayed old manifest from
		// reintroducing a fixed bug. AllowDowngrade is the signed, deliberate
		// exception for recalling a bad release.
		return Decision{Reason: fmt.Sprintf("%s is older than the installed %s", m.Version, current)}
	}

	if !InRollout(st.InstallID, m.Version, m.Rollout) {
		return Decision{Reason: fmt.Sprintf("not in the %d%% rollout for %s", m.Rollout, m.Version)}
	}

	// Checked last, after everything that would have skipped this release
	// anyway. A client not in the rollout, or already poisoned against this
	// version, has no reinstall to perform and should not be told otherwise.
	if m.RequiresReinstall {
		return Decision{
			Reinstall:    true,
			InstallerURL: m.InstallerURL,
			Reason: fmt.Sprintf("%s cannot be installed by the agent; a new installer is required from %s",
				m.Version, m.InstallerURL),
		}
	}

	artifact, ok := m.Artifact(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return Decision{Reason: fmt.Sprintf("no %s/%s artifact in %s", runtime.GOOS, runtime.GOARCH, m.Version)}
	}

	return Decision{Apply: true, Artifact: artifact, Reason: fmt.Sprintf("updating to %s", m.Version)}
}

// InRollout buckets an install deterministically into a staged rollout.
//
// Two properties matter, and both are tested:
//
//   - Monotonic in percent. A client admitted at 10% is still admitted at 50%,
//     so raising the dial only ever adds clients. If it reshuffled, widening a
//     rollout could tell an already-updated client it is no longer eligible.
//   - Resampled per version. Hashing the version alongside the install ID means
//     each release draws an independent sample, so the same unlucky installs
//     are not the canary every single time.
func InRollout(installID, releaseVersion string, percent int) bool {
	switch {
	case percent >= 100:
		return true
	case percent <= 0:
		return false
	}
	h := fnv.New32a()
	h.Write([]byte(installID + "|" + releaseVersion))
	return int(h.Sum32()%100) < percent
}
