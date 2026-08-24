// Package updater is the program's half of the update mechanism.
//
// It polls a release channel, decides whether a release applies here, downloads
// and verifies it, proves the candidate can actually execute, stages it, and
// then exits so the shim can install it at the next start.
//
// It never replaces a running binary. That is the shim's job, and the split is
// what keeps this package free of platform-specific swap logic.
package updater

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/events"
	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/staging"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
)

// SelfCheckFlag is the contract a candidate binary must satisfy: print its
// version to stdout, exit 0, and touch nothing else.
const SelfCheckFlag = "--self-check"

// Poll interval bounds. The manifest can ask for a different cadence, but not
// an unreasonable one — a hostile or malformed value must not be able to turn
// the fleet into a tight loop.
const (
	MinInterval     = 30 * time.Second
	MaxInterval     = 24 * time.Hour
	DefaultInterval = 15 * time.Minute
)

// Sentinel outcomes. Both end the poll loop; the caller shuts down and lets the
// supervisor restart into the shim.
var (
	// ErrUpdateStaged means a new version is on disk awaiting the next start.
	ErrUpdateStaged = errors.New("update staged, restart required")

	// ErrTooStale means this build is below the minimum supported version and
	// must not keep running.
	ErrTooStale = errors.New("this version is no longer supported")
)

// Config wires the updater to its surroundings.
type Config struct {
	Layout      layout.Layout
	ManifestURL string
	TrustedKeys []ed25519.PublicKey
	Version     string

	// Interval is the fallback poll cadence, used until a manifest expresses a
	// preference via next_check_seconds.
	Interval time.Duration

	// CanUpdate is consulted immediately before staging. Returning false defers
	// to the next poll, which is the hook for "not while a job is in flight".
	// Deferring is cheap, so it is safe to be conservative here.
	CanUpdate func() bool

	Client   *http.Client
	Logger   *slog.Logger
	Events   *events.Log
	Reporter events.Reporter
	Store    *state.Store
}

// Updater polls a channel and stages updates.
type Updater struct {
	cfg      Config
	log      *slog.Logger
	source   *Source
	state    *state.State
	interval time.Duration
	failures int
}

// New validates configuration and loads persisted state.
func New(cfg Config) (*Updater, error) {
	switch {
	case cfg.ManifestURL == "":
		return nil, errors.New("updater: ManifestURL is required")
	case len(cfg.TrustedKeys) == 0:
		return nil, errors.New("updater: at least one trusted key is required")
	case cfg.Store == nil:
		return nil, errors.New("updater: Store is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Minute}
	}

	st, err := cfg.Store.Load()
	if err != nil {
		return nil, fmt.Errorf("updater: load state: %w", err)
	}

	agent := UserAgent(layout.AppName, cfg.Version)
	return &Updater{
		cfg:      cfg,
		log:      cfg.Logger.With("component", "updater"),
		source:   NewSource(cfg.ManifestURL, cfg.TrustedKeys, cfg.Client, agent),
		state:    st,
		interval: cfg.Interval,
	}, nil
}

// State exposes the loaded state, for status output.
func (u *Updater) State() *state.State { return u.state }

// MarkHealthy commits a pending update.
//
// The program decides what healthy means and calls this once it is genuinely
// running. Until then the shim is counting boots, and a version that never gets
// here is rolled back. This is the only place a trial is resolved successfully,
// which is why it is a no-op rather than an error when nothing is pending.
func (u *Updater) MarkHealthy() {
	if u.state.PendingVersion != u.cfg.Version || u.state.PendingVersion == "" {
		return
	}
	previous := u.state.PreviousVersion
	attempts := u.state.BootAttempts

	u.state.Commit(u.cfg.Version)
	u.save()

	// The backup has served its purpose. Keeping it would mean every client
	// retains a second copy of every binary it has ever run.
	if err := os.Remove(u.cfg.Layout.BackupProgram()); err != nil && !os.IsNotExist(err) {
		u.log.Debug("could not remove backup", "error", err)
	}

	u.log.Info("update committed", "version", u.cfg.Version, "from", previous, "boots", attempts)
	u.record(events.KindCommitted, map[string]string{"from": previous})
}

// Run checks once immediately, then polls until the context is cancelled, an
// update is staged, or this build is found to be unsupported.
//
// The first check is deliberately not deferred to the first tick. A machine that
// has been switched off for months comes back on a stale build, and waiting a
// full interval before finding out means it spends that window running a version
// that may be known-bad — or one already below min_supported_version, which is
// the condition the floor exists to catch. For a security-relevant agent that
// window is the whole point.
func (u *Updater) Run(ctx context.Context) error {
	u.log.Info("update checks started",
		"version", u.cfg.Version,
		"channel", u.cfg.ManifestURL,
		"interval", u.interval,
		"install_id", u.state.InstallID)

	first := true

	for {
		if !first {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(u.nextDelay()):
			}
		}
		first = false

		err := u.CheckNow(ctx)
		u.deliverEvents(ctx)

		switch {
		case err == nil:
			u.failures = 0
		case errors.Is(err, ErrUpdateStaged), errors.Is(err, ErrTooStale):
			return err
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			u.failures++
			u.logCheckFailure(ctx, err)
		}
	}
}

// CheckNow performs one poll. It returns ErrUpdateStaged when an update is
// ready to install, or ErrTooStale when this build must stop running.
func (u *Updater) CheckNow(ctx context.Context) error {
	m, err := u.source.Manifest(ctx)
	if errors.Is(err, ErrNotModified) {
		u.noteCheck()
		return nil
	}
	if err != nil {
		return err
	}

	u.interval = m.NextCheck(u.cfg.Interval, MinInterval, MaxInterval)
	u.noteCheck()

	decision := Evaluate(m, u.cfg.Version, u.state)
	switch {
	case decision.Reinstall:
		u.reportReinstallRequired(ctx, m.Version, decision)
		return nil
	case decision.Stop:
		u.log.Error("this build is no longer supported; stopping", "reason", decision.Reason)
		u.record(events.KindStale, map[string]string{"reason": decision.Reason})
		u.deliverEvents(ctx)
		return fmt.Errorf("%w: %s", ErrTooStale, decision.Reason)
	case !decision.Apply:
		u.log.Debug("no update applied", "offered", m.Version, "reason", decision.Reason)
		return nil
	}

	// A release we can install supersedes any earlier reinstall requirement.
	u.state.ClearReinstall()

	if u.cfg.CanUpdate != nil && !u.cfg.CanUpdate() {
		u.log.Info("update deferred by the application", "version", m.Version)
		return nil
	}
	if err := u.cfg.Layout.Writable(); err != nil {
		return err
	}

	u.log.Info("update available", "from", u.cfg.Version, "to", m.Version, "notes", m.Notes)
	u.record(events.KindUpdateFound, map[string]string{"to": m.Version})

	return u.stage(ctx, m.Version, decision)
}

// reportReinstallRequired surfaces a release the agent cannot install itself.
//
// The client keeps running: it is on a working version, and the alternative —
// stopping — would take a functioning machine offline over a packaging change.
// The requirement is logged and reported once per version rather than on every
// poll, and stays visible in --status until a release supersedes it. If the
// current version later falls below min_supported_version, the ordinary
// staleness path stops the agent, which is the real deadline.
func (u *Updater) reportReinstallRequired(ctx context.Context, newVersion string, d Decision) {
	if !u.state.NeedsReinstall(newVersion) {
		u.log.Debug("reinstall still required", "version", newVersion)
		return
	}
	u.save()

	u.log.Warn("a new installer is required",
		"running", u.cfg.Version,
		"available", newVersion,
		"installer", d.InstallerURL,
		"detail", "this release changes components the agent does not own, so it cannot install itself")

	u.record(events.KindReinstall, map[string]string{
		"available": newVersion,
		"installer": d.InstallerURL,
	})
	u.deliverEvents(ctx)
}

// stage downloads, verifies, proves and records a candidate.
func (u *Updater) stage(ctx context.Context, newVersion string, d Decision) error {
	target := u.cfg.Layout.Program()
	staged := u.cfg.Layout.StagedProgram()

	path, err := u.source.Download(ctx, d.Artifact, filepath.Dir(staged), filepath.Base(staged))
	if err != nil {
		u.record(events.KindUpdateFailed, map[string]string{"to": newVersion, "error": err.Error()})
		return err
	}

	if err := u.preflight(ctx, path, newVersion); err != nil {
		// The download was authentic — it matched a signed manifest — but it
		// cannot run here. Poison it so the next poll does not fetch the same
		// bytes again, and leave the install untouched.
		os.Remove(path)
		u.state.Poison(newVersion)
		u.save()
		u.log.Error("candidate rejected", "version", newVersion, "error", err)
		u.record(events.KindUpdateRejected, map[string]string{"to": newVersion, "error": err.Error()})
		return fmt.Errorf("candidate %s rejected: %w", newVersion, err)
	}

	digest, _, err := fsutil.SHA256File(path)
	if err != nil {
		os.Remove(path)
		return err
	}
	record := staging.Record{
		Target:      target,
		Staged:      path,
		Version:     newVersion,
		FromVersion: u.cfg.Version,
		SHA256:      digest,
	}
	if err := staging.Write(u.cfg.Layout.StagingRecord(), record); err != nil {
		os.Remove(path)
		return err
	}

	u.log.Info("update staged; exiting so the shim can install it",
		"from", u.cfg.Version, "to", newVersion)
	u.record(events.KindUpdateStaged, map[string]string{"to": newVersion})
	return ErrUpdateStaged
}

// preflight runs the candidate once, before it is installed, and requires it to
// identify itself correctly.
//
// This is the cheap answer to the worst failure an updater can cause: shipping
// a build that never starts. Wrong architecture, a missing shared library, a
// Gatekeeper refusal, a proxy that truncated the transfer while reporting a
// full Content-Length, a release pipeline that put the wrong binary in the
// wrong slot — none of those are caught by a signature or a digest, and none
// can be caught by boot counting either, because nothing would ever run to do
// the counting. Executing the candidate catches them all while the working
// binary is still installed and abandoning the update costs nothing.
func (u *Updater) preflight(ctx context.Context, path, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, SelfCheckFlag).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return fmt.Errorf("self-check exited %d: %s",
				exitErr.ExitCode(), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return fmt.Errorf("self-check did not run: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		// The manifest and the artifact disagree. The signature covered the
		// manifest, so this is a release-process error rather than an attack —
		// but installing it would corrupt our record of what is deployed and
		// break every version comparison from here on.
		return fmt.Errorf("self-check reported %q, manifest declares %q", got, want)
	}
	return nil
}

// nextDelay jitters the interval and backs off after consecutive failures, so a
// channel having a bad day is not additionally hammered by the whole fleet
// retrying in lockstep.
func (u *Updater) nextDelay() time.Duration {
	d := u.interval
	if u.failures > 0 {
		shift := min(u.failures, 5) // cap the multiplier at 32x
		d *= 1 << shift
	}
	if d > MaxInterval {
		d = MaxInterval
	}
	jitter := 1 + (rand.Float64()-0.5)/2 // [0.75, 1.25)
	return time.Duration(float64(d) * jitter)
}

// logCheckFailure raises the level with the failure count. A single failed poll
// is normal — laptops sleep, networks drop, servers deploy — and is only worth
// attention once it persists.
func (u *Updater) logCheckFailure(ctx context.Context, err error) {
	level := slog.LevelInfo
	if u.failures >= 5 {
		level = slog.LevelWarn
	}
	u.log.Log(ctx, level, "update check failed", "error", err, "consecutive_failures", u.failures)
}

func (u *Updater) deliverEvents(ctx context.Context) {
	if u.cfg.Events == nil || u.cfg.Reporter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := u.cfg.Events.Deliver(ctx, u.cfg.Reporter); err != nil {
		// Events stay on disk and go out next time. Never fatal: telemetry
		// must not break the thing it reports on.
		u.log.Debug("could not deliver events", "error", err)
	}
}

func (u *Updater) record(kind string, fields map[string]string) {
	if u.cfg.Events != nil {
		u.cfg.Events.Record(kind, u.cfg.Version, fields)
	}
}

func (u *Updater) noteCheck() {
	u.state.LastCheck = time.Now().UTC()
	u.save()
}

func (u *Updater) save() {
	if err := u.cfg.Store.Save(u.state); err != nil {
		// State is a hint, not the source of truth, so this is not fatal. It
		// does cost rollback protection for an update in flight, so it is worth
		// a warning rather than a debug line.
		u.log.Warn("could not persist state", "path", u.cfg.Store.Path(), "error", err)
	}
}
