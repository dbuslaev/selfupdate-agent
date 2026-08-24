package updater

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/dbuslaev/selfupdate-agent/internal/manifest"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
)

func offeredManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Version: "1.1.0",
		Rollout: 100,
		Artifacts: []manifest.Artifact{{
			OS:     runtime.GOOS,
			Arch:   runtime.GOARCH,
			URL:    "artifacts/agent-app",
			SHA256: strings.Repeat("00", 32),
			Size:   1,
		}},
	}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name      string
		current   string
		mutate    func(*manifest.Manifest)
		prepare   func(*state.State)
		wantApply bool
		wantStop  bool
		reason    string
	}{
		{
			name: "a newer release applies", current: "1.0.0", wantApply: true,
		},
		{
			name: "the same version is a no-op", current: "1.1.0",
			reason: "already on this version",
		},
		{
			name: "an older release is refused", current: "1.2.0",
			reason: "older than",
		},
		{
			name:    "an older release applies when the manifest allows a downgrade",
			current: "1.2.0",
			mutate:  func(m *manifest.Manifest) { m.AllowDowngrade = true },
			// The recall path: a signed manifest is the only thing that can
			// move the fleet backwards.
			wantApply: true,
		},
		{
			name:    "a client below min_supported_version stops",
			current: "1.0.0",
			mutate:  func(m *manifest.Manifest) { m.MinSupportedVersion = "1.0.5" },
			// The staleness backstop: this is what stops a rollback from
			// pinning a client to an old build indefinitely.
			wantStop: true,
			reason:   "below the minimum supported version",
		},
		{
			name:    "a version that already failed here is not retried",
			current: "1.0.0",
			prepare: func(s *state.State) { s.Poison("1.1.0") },
			reason:  "previously failed",
		},
		{
			name:    "a zero rollout reaches nobody",
			current: "1.0.0",
			mutate:  func(m *manifest.Manifest) { m.Rollout = 0 },
			reason:  "rollout",
		},
		{
			name:    "a missing platform artifact is reported",
			current: "1.0.0",
			mutate:  func(m *manifest.Manifest) { m.Artifacts[0].OS = "plan9" },
			reason:  "artifact",
		},
		{
			name:    "an unorderable version is never installed",
			current: "1.0.0",
			mutate:  func(m *manifest.Manifest) { m.Version = "latest" },
			reason:  "cannot be ordered",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := offeredManifest()
			if c.mutate != nil {
				c.mutate(m)
			}
			st := state.New()
			st.InstallID = "install-under-test"
			if c.prepare != nil {
				c.prepare(st)
			}

			got := Evaluate(m, c.current, st)

			if got.Apply != c.wantApply {
				t.Errorf("Apply = %v, want %v (reason: %s)", got.Apply, c.wantApply, got.Reason)
			}
			if got.Stop != c.wantStop {
				t.Errorf("Stop = %v, want %v (reason: %s)", got.Stop, c.wantStop, got.Reason)
			}
			if got.Reason == "" {
				t.Error("every decision must carry a reason; a silent skip is undebuggable from outside")
			}
			if c.reason != "" && !strings.Contains(got.Reason, c.reason) {
				t.Errorf("reason = %q, want it to mention %q", got.Reason, c.reason)
			}
		})
	}
}

// The staleness check must win over everything, including a poisoned version:
// a client below the supported floor has to stop even when no update is
// available to it.
func TestStopBeatsOtherReasons(t *testing.T) {
	m := offeredManifest()
	m.MinSupportedVersion = "2.0.0"

	st := state.New()
	st.Poison(m.Version)

	if got := Evaluate(m, "1.0.0", st); !got.Stop {
		t.Fatalf("expected Stop, got reason %q", got.Reason)
	}
}

// Monotonic in percent: a client admitted at 10% must still be admitted at 50%.
// If it were not, raising the dial could tell an already-updated client it is
// no longer eligible, and widening a rollout would reshuffle the fleet instead
// of extending it.
func TestRolloutIsMonotonic(t *testing.T) {
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		admitted := false
		for percent := 0; percent <= 100; percent++ {
			in := InRollout(id, "2.0.0", percent)
			if admitted && !in {
				t.Fatalf("install %q was admitted below %d%% but excluded at %d%%", id, percent, percent)
			}
			admitted = admitted || in
		}
		if !admitted {
			t.Fatalf("install %q was never admitted, even at 100%%", id)
		}
	}
}

// The bucket must not move between polls, or a client would flap in and out of
// a rollout as it checks.
func TestRolloutIsStable(t *testing.T) {
	want := InRollout("install", "2.0.0", 37)
	for i := 0; i < 50; i++ {
		if got := InRollout("install", "2.0.0", 37); got != want {
			t.Fatalf("the rollout decision changed on check %d", i)
		}
	}
}

// Each release should sample the fleet independently, so the same unlucky
// installs are not the canary every time.
func TestRolloutResamplesPerVersion(t *testing.T) {
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("install-%d", i)
		if InRollout(id, "2.0.0", 50) != InRollout(id, "2.0.1", 50) {
			return // found an install bucketed differently across two releases
		}
	}
	t.Fatal("rollout buckets are identical across versions; canaries would never rotate")
}

// A release the agent cannot install must be reported rather than attempted,
// and must not be confused with a release that does not apply.
func TestEvaluateReportsReinstallRequirement(t *testing.T) {
	m := offeredManifest()
	m.RequiresReinstall = true
	m.InstallerURL = "https://example.com/install"

	st := state.New()
	got := Evaluate(m, "1.0.0", st)

	if !got.Reinstall {
		t.Fatalf("Reinstall = false, want true (reason: %s)", got.Reason)
	}
	if got.Apply {
		t.Error("a release requiring a reinstall must not be downloaded")
	}
	if got.InstallerURL != m.InstallerURL {
		t.Errorf("InstallerURL = %q, want it carried through for the operator", got.InstallerURL)
	}
}

// The reinstall check runs last, so a client that would have skipped the
// release anyway is not told to go and reinstall for nothing.
func TestReinstallIsNotReportedToClientsTheReleaseDoesNotReach(t *testing.T) {
	cases := map[string]func(*manifest.Manifest, *state.State){
		"not in the rollout": func(m *manifest.Manifest, _ *state.State) { m.Rollout = 0 },
		"already poisoned":   func(m *manifest.Manifest, s *state.State) { s.Poison(m.Version) },
		"older release":      func(m *manifest.Manifest, _ *state.State) { m.Version = "0.9.0" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := offeredManifest()
			m.RequiresReinstall = true
			m.InstallerURL = "https://example.com/install"
			st := state.New()
			mutate(m, st)

			if got := Evaluate(m, "1.0.0", st); got.Reinstall {
				t.Errorf("reported a reinstall requirement to a client the release does not reach (%s)", got.Reason)
			}
		})
	}
}

// Being unable to install is not a reason to keep running an unsupported build.
func TestStaleBeatsReinstall(t *testing.T) {
	m := offeredManifest()
	m.RequiresReinstall = true
	m.InstallerURL = "https://example.com/install"
	m.MinSupportedVersion = "1.0.5"

	if got := Evaluate(m, "1.0.0", state.New()); !got.Stop {
		t.Fatalf("expected Stop to win, got reason %q", got.Reason)
	}
}
