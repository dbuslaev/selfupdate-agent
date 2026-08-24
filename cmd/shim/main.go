// Command shim is what the supervisor launches.
//
// It exists because a program cannot safely replace itself while it is running.
// The shim runs at a moment when the program is not executing, so installing an
// update is two ordinary renames — identical on every platform, with no window
// in which the binary is missing.
//
// It is deliberately small and deliberately dumb. It never decides what to
// install: no manifest parsing, no rollout logic, no release signing key, no
// choice about versions. It installs what the program already downloaded and
// verified, and nothing else.
//
// It is not entirely inert. It loads this machine's own key to sign a startup
// report, which is its one network call, hard-limited to three seconds so a slow
// endpoint can never delay the program. And it makes exactly one decision — that
// a pending version has failed often enough to be rolled back — which lives here
// because the shim is the only thing guaranteed to run on every start.
//
// Everything that changes often lives in the program, which ships often;
// everything here almost never changes, which is what keeps "who updates the
// updater" from being a real problem.
//
// Its sequence on every start:
//
// The shim is argument-transparent: every argument it receives is passed
// through to the program untouched, and its own configuration comes from the
// environment. It has to be. A supervisor invokes the shim but is configuring
// the program, so if the shim parsed those arguments it would reject the ones
// it does not recognise and nothing would start. The single exception is
// --self-check, which must answer for the shim binary itself.
//
// Its sequence on every start:
//
//  1. install a staged program, if the program left one
//  2. count this boot, and roll back if the pending version has had enough
//     chances
//  3. report what happened, with a hard timeout
//  4. hand over to the program
//
// Step 2 is the reason boot counting lives here rather than in the program: the
// shim is the only thing guaranteed to run on every start, so it is the only
// place that can notice a build which dies before it can count itself.
//
// The shim never replaces itself. A release that changes the shim or the
// service definition is marked requires_reinstall in the manifest, and the
// program tells the operator to run a new installer. Self-replacement was
// possible to build and not worth it: a mechanism that runs approximately never
// is a mechanism that is never exercised, and the failure would surface on a
// client during the one update that mattered.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/events"
	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
	"github.com/dbuslaev/selfupdate-agent/internal/identity"
	"github.com/dbuslaev/selfupdate-agent/internal/launch"
	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/staging"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
	"github.com/dbuslaev/selfupdate-agent/internal/updater"
	"github.com/dbuslaev/selfupdate-agent/internal/version"
)

// maxBootAttempts is how many times a pending version may start without
// reporting healthy before its predecessor is restored.
const maxBootAttempts = 3

// reportTimeout bounds the check-in. The shim sits on the startup path, so a
// slow or unreachable API must never delay the program — and must never prevent
// it from starting at all.
const reportTimeout = 3 * time.Second

func main() {
	// Answer for ourselves rather than the program. The installer uses this to
	// confirm which shim it placed.
	if hasArg(updater.SelfCheckFlag) {
		fmt.Println(version.Version)
		return
	}

	log := newLogger(os.Getenv(envDebug) != "")

	if err := run(log, os.Getenv(envReportURL)); err != nil {
		log.Error("shim failed", "error", err)
		os.Exit(1)
	}
}

// Environment configuration. Flags are unavailable to the shim because every
// argument belongs to the program; a service definition sets these instead.
const (
	envReportURL = "AGENT_REPORT_URL"
	envDebug     = "AGENT_DEBUG"
)

// hasArg reports whether name appears in the arguments, accepting both the
// single- and double-dash spellings that Go's flag package treats as
// equivalent.
func hasArg(name string) bool {
	bare := strings.TrimLeft(name, "-")
	for _, arg := range os.Args[1:] {
		if arg == "-"+bare || arg == "--"+bare {
			return true
		}
	}
	return false
}

func run(log *slog.Logger, reportURL string) error {
	paths, err := layout.Resolve()
	if err != nil {
		return err
	}
	if err := paths.EnsureDataDir(); err != nil {
		return err
	}

	eventLog := events.NewLog(paths.EventLog(), "shim")
	store := state.NewStore(paths.StateFile())

	st, err := store.Load()
	if err != nil {
		return err
	}

	installStagedProgram(log, paths, st, eventLog)
	resolveTrial(log, paths, st, eventLog)

	if err := store.Save(st); err != nil {
		// A failure here loses boot counting for this cycle. Worth saying, not
		// worth refusing to start over.
		log.Warn("could not persist state", "error", err)
	}

	eventLog.Record(events.KindShimStart, version.Version, map[string]string{
		"program_version": programVersion(paths),
		"pending":         st.PendingVersion,
		"boot_attempts":   fmt.Sprint(st.BootAttempts),
	})
	deliver(log, paths, eventLog, reportURL)

	return handOver(log, paths)
}

// installStagedProgram applies a program update left by the previous run.
//
// Nothing is running from the target path at this point, which is what makes
// this safe. A verification failure is not fatal: the staged file is discarded
// and the working binary is launched instead.
func installStagedProgram(log *slog.Logger, paths layout.Layout, st *state.State, eventLog *events.Log) {
	record, found, err := staging.Read(paths.StagingRecord())
	if err != nil {
		log.Error("discarding unreadable staging record", "error", err)
		fsutil.Remove(paths.StagingRecord())
		fsutil.Remove(paths.StagedProgram())
		return
	}
	if !found {
		return
	}

	if err := staging.Apply(record, paths.BackupProgram()); err != nil {
		log.Error("could not install staged update", "version", record.Version, "error", err)
		eventLog.Record(events.KindUpdateFailed, record.FromVersion, map[string]string{
			"to": record.Version, "error": err.Error(),
		})
		st.Poison(record.Version)
		staging.Clear(paths.StagingRecord(), record)
		return
	}

	// The new binary is installed but unproven. From here the program must
	// reach MarkHealthy or resolveTrial will put the old one back.
	st.BeginTrial(record.Version, record.FromVersion)
	staging.Clear(paths.StagingRecord(), record)

	log.Info("installed staged update", "from", record.FromVersion, "to", record.Version)
	eventLog.Record(events.KindShimSwap, record.Version, map[string]string{"from": record.FromVersion})
}

// resolveTrial counts this boot and rolls back a version that has had enough
// chances.
//
// Counting here rather than in the program is what closes the last hole. A
// build that panics during initialisation, fails to load a library, or is
// killed on startup never gets to count itself — but the shim runs regardless,
// so the count still advances and the rollback still happens.
func resolveTrial(log *slog.Logger, paths layout.Layout, st *state.State, eventLog *events.Log) {
	if !st.OnTrial() {
		return
	}

	attempts := st.RecordBoot()
	if attempts <= maxBootAttempts {
		log.Info("pending version on trial",
			"version", st.PendingVersion, "attempt", attempts, "of", maxBootAttempts)
		return
	}

	failed, restoring := st.PendingVersion, st.PreviousVersion
	log.Error("pending version never reported healthy; rolling back",
		"version", failed, "attempts", attempts, "restoring", restoring)

	if err := staging.Restore(paths.Program(), paths.BackupProgram()); err != nil {
		// The failing binary cannot be replaced. Launch it anyway: a program
		// that keeps crashing is still more recoverable than one that never
		// starts, and the operator needs the machine reporting.
		log.Error("rollback failed; manual recovery required", "error", err)
		eventLog.Record(events.KindShimRollback, failed, map[string]string{
			"outcome": "failed", "error": err.Error(),
		})
		return
	}

	// Poison the failed version so the restored program does not immediately
	// download and install the same broken build again.
	st.Abandon(restoring)
	eventLog.Record(events.KindShimRollback, failed, map[string]string{
		"outcome": "restored", "restored": restoring, "attempts": fmt.Sprint(attempts),
	})
}

// deliver flushes buffered events, including anything the previous run could
// not send. Best effort and time-boxed: the program must start regardless.
func deliver(log *slog.Logger, paths layout.Layout, eventLog *events.Log, reportURL string) {
	if reportURL == "" {
		return
	}
	id, found, err := identity.Load(paths.IdentityFile())
	if err != nil || !found {
		log.Debug("no identity; skipping check-in", "error", err)
		return
	}
	signer, err := identity.NewSigner(id)
	if err != nil {
		log.Debug("unusable identity; skipping check-in", "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), reportTimeout)
	defer cancel()

	reporter := events.NewHTTPReporter(reportURL, signer, reportTimeout)
	if err := eventLog.Deliver(ctx, reporter); err != nil {
		// Events stay on disk and go out on the next start or from the program.
		log.Debug("check-in failed; events retained", "error", err)
	}
}

// handOver launches the program. On Unix this does not return.
func handOver(log *slog.Logger, paths layout.Layout) error {
	program := paths.Program()
	if !fsutil.Exists(program) {
		return fmt.Errorf("no program at %s; the install is incomplete", program)
	}

	// argv[0] is the program's own path; every remaining argument is forwarded
	// verbatim. This is the transparency contract: the supervisor configures
	// the program, and the shim is only the name it is reached through.
	args := append([]string{program}, os.Args[1:]...)

	code, err := launch.Program(program, args, os.Environ())
	if err != nil {
		return err
	}
	log.Info("program exited", "code", code)
	os.Exit(code)
	return nil
}

// programVersion asks the installed program to identify itself, for the
// check-in payload. Best effort: an unreadable version is reported as unknown
// rather than blocking startup.
func programVersion(paths layout.Layout) string {
	out, err := runSelfCheck(paths.Program())
	if err != nil {
		return "unknown"
	}
	return out
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).
		With("component", "shim", "shim_version", version.Version)
}
