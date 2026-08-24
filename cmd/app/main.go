// Command agent-app is the program the shim launches. In a real deployment
// this is the product; here it prints a heartbeat so that an update, and a
// rollback, are visible in a terminal.
//
// What is worth reading is not the work it does but how it is wired:
//
//   - the trusted release key is compiled in, so tampering with the install
//     directory cannot change what the program is willing to install;
//   - it never replaces its own binary — it stages and exits, and the shim
//     installs at the next start;
//   - MarkHealthy is called only after the program has actually been running,
//     which is what turns the shim's boot counter into working rollback;
//   - the worker and the updater share one context, so exiting to update drains
//     in-flight work instead of abandoning it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/events"
	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
	"github.com/dbuslaev/selfupdate-agent/internal/updater"
	"github.com/dbuslaev/selfupdate-agent/internal/version"
)

// Exit codes. A supervisor configured with Restart=always does not need to
// distinguish them, but they make the reason visible in `systemctl status` and
// in the Windows event log.
const (
	exitOK       = 0 // clean shutdown, or exiting so an update can be installed
	exitError    = 1 // unexpected failure
	exitTooStale = 2 // below the minimum supported version; do not restart
)

func main() {
	opts := parseFlags()

	// The self-check contract: print the version, exit 0, touch nothing. Both
	// the updater and the shim run this against binaries that may not be
	// installed yet, so it must not open listeners, write state, or read
	// configuration that might be absent.
	if opts.selfCheck {
		fmt.Println(version.Version)
		return
	}

	log := newLogger(opts.verbose)
	slog.SetDefault(log)

	if opts.status {
		if err := printStatus(os.Stdout); err != nil {
			log.Error("could not read status", "error", err)
			os.Exit(exitError)
		}
		return
	}

	os.Exit(run(log, opts))
}

type options struct {
	selfCheck   bool
	status      bool
	verbose     bool
	manifestURL string
	reportURL   string
	interval    time.Duration
	healthyshim time.Duration
	heartbeat   time.Duration
}

func parseFlags() options {
	var o options
	flag.BoolVar(&o.selfCheck, "self-check", false, "print version and exit")
	flag.BoolVar(&o.status, "status", false, "print install status and exit")
	flag.BoolVar(&o.verbose, "v", false, "debug logging")
	flag.StringVar(&o.manifestURL, "manifest", os.Getenv("AGENT_MANIFEST_URL"), "signed release manifest URL")
	flag.StringVar(&o.reportURL, "report-url", os.Getenv("AGENT_REPORT_URL"), "fleet API endpoint for events")
	flag.DurationVar(&o.interval, "interval", updater.DefaultInterval, "fallback poll interval")
	flag.DurationVar(&o.healthyshim, "healthy-after", 30*time.Second, "how long a new version must run before its update commits")
	flag.DurationVar(&o.heartbeat, "heartbeat", 5*time.Second, "heartbeat period")
	flag.Parse()
	return o
}

func run(log *slog.Logger, opts options) int {
	// One context for the whole process. Cancelling it stops the worker and the
	// updater together, whether the trigger is SIGTERM, Ctrl-C, or an update
	// that wants us to make way.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	paths, err := layout.Resolve()
	if err != nil {
		log.Error("could not resolve install layout", "error", err)
		return exitError
	}
	if err := paths.EnsureDataDir(); err != nil {
		log.Error("could not prepare data directory", "error", err)
		return exitError
	}

	eventLog := events.NewLog(paths.EventLog(), "app")
	defer capturePanic(log, eventLog)

	up, err := newUpdater(log, paths, eventLog, opts)
	if err != nil {
		log.Error("could not start the updater", "error", err)
		return exitError
	}

	var wg sync.WaitGroup
	startWorker(ctx, &wg, log, opts.heartbeat)

	if up == nil {
		log.Warn("updates disabled: no manifest URL, or no release key compiled in")
		<-ctx.Done()
		wg.Wait()
		return exitOK
	}

	// Commit the pending update only once this build has proven it can stay up.
	// A version that dies before this fires leaves the shim's boot counter
	// climbing, and after enough attempts its predecessor is restored.
	startHealthTimer(ctx, &wg, up, opts.healthyshim)

	runErr := up.Run(ctx)

	stop()
	wg.Wait() // let the worker finish its current beat rather than vanishing

	return reportOutcome(log, eventLog, runErr)
}

// reportOutcome turns the updater's terminal error into an exit code.
func reportOutcome(log *slog.Logger, eventLog *events.Log, err error) int {
	switch {
	case errors.Is(err, updater.ErrUpdateStaged):
		log.Info("exiting so the shim can install the staged update")
		return exitOK

	case errors.Is(err, updater.ErrTooStale):
		// Deliberately a distinct code. This is the one exit a supervisor
		// should not paper over by restarting: the build is below the supported
		// floor and needs a reinstall or an administrator.
		log.Error("stopping: this version is no longer supported", "error", err)
		return exitTooStale

	case errors.Is(err, context.Canceled), err == nil:
		log.Info("shutting down")
		eventLog.Record(events.KindShutdown, version.Version, nil)
		return exitOK
	}

	log.Error("updater stopped unexpectedly", "error", err)
	return exitError
}

// startWorker runs the thing this program actually exists to do.
func startWorker(ctx context.Context, wg *sync.WaitGroup, log *slog.Logger, period time.Duration) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(period)
		defer ticker.Stop()

		for beat := 1; ; beat++ {
			select {
			case <-ctx.Done():
				log.Info("worker stopped", "beats", beat-1)
				return
			case <-ticker.C:
				log.Info("heartbeat", "n", beat)
			}
		}
	}()
}

// startHealthTimer commits a pending update once the program has stayed up long
// enough. A real program would gate this on something meaningful — listeners
// bound, migrations applied, a first successful request — rather than elapsed
// time.
func startHealthTimer(ctx context.Context, wg *sync.WaitGroup, up *updater.Updater, after time.Duration) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
		case <-time.After(after):
			up.MarkHealthy()
		}
	}()
}

// capturePanic records a crash before the process dies, so the next start can
// report it. Writing locally and delivering later is what makes a crash on a
// disconnected machine still visible once it reconnects.
func capturePanic(log *slog.Logger, eventLog *events.Log) {
	r := recover()
	if r == nil {
		return
	}
	eventLog.Record(events.KindPanic, version.Version, map[string]string{
		"panic": fmt.Sprint(r),
	})
	log.Error("panic", "value", r)
	panic(r)
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).
		With("version", version.Version, "pid", os.Getpid())
}

// printStatus is the operator-facing view: what is installed, what is pending,
// what has failed here, and what the agent has been doing.
func printStatus(w *os.File) error {
	paths, err := layout.Resolve()
	if err != nil {
		return err
	}
	st, err := state.NewStore(paths.StateFile()).Load()
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "version:        %s\n", version.Version)
	fmt.Fprintf(w, "install id:     %s\n", st.InstallID)
	fmt.Fprintf(w, "install dir:    %s\n", paths.InstallDir)
	fmt.Fprintf(w, "data dir:       %s\n", paths.DataDir)
	fmt.Fprintf(w, "last committed: %s\n", orNone(st.LastCommitted))
	fmt.Fprintf(w, "last check:     %s\n", orNever(st.LastCheck))

	if st.OnTrial() {
		fmt.Fprintf(w, "pending:        %s (boot %d)\n", st.PendingVersion, st.BootAttempts)
	}
	if st.ReinstallFor != "" {
		// Deliberately prominent. This is the one condition the agent cannot
		// resolve on its own, so it has to stay visible until a person acts.
		fmt.Fprintf(w, "\nACTION REQUIRED: version %s cannot be installed by the agent.\n", st.ReinstallFor)
		fmt.Fprintf(w, "                 Run a new installer to move past it.\n")
	}
	if len(st.Poisoned) > 0 {
		fmt.Fprintf(w, "failed here:    %v\n", st.Poisoned)
	}

	recent, err := events.NewLog(paths.EventLog(), "app").Tail(10)
	if err != nil || len(recent) == 0 {
		return err
	}
	fmt.Fprintf(w, "\nrecent events:\n")
	for _, ev := range recent {
		fmt.Fprintf(w, "  %s  %-20s %s %v\n",
			ev.Time.Format(time.RFC3339), ev.Kind, ev.Version, ev.Fields)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func orNever(t time.Time) string {
	if t.IsZero() {
		return "(never)"
	}
	return t.Format(time.RFC3339)
}
