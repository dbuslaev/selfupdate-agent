// Command installer performs a first install, an upgrade over an existing
// install, or an uninstall.
//
// It does the three things the running agent cannot do for itself: place both
// binaries, obtain an identity, and register the shim with the platform's
// supervisor. After that the agent maintains itself and the installer is not
// needed again — the manifest's requires-reinstall path exists for the rare
// release that changes the service definition, and should essentially never be
// used.
//
// Installing is idempotent. Running it over an existing install stops the
// service, replaces the binaries, and starts it again, so the same command
// works for a first install and a repair.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
	"github.com/dbuslaev/selfupdate-agent/internal/identity"
	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/service"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
	"github.com/dbuslaev/selfupdate-agent/internal/updater"
	"github.com/dbuslaev/selfupdate-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = install(os.Args[2:])
	case "uninstall":
		err = uninstall(os.Args[2:])
	case "version":
		fmt.Println(version.Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "installer:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  installer install   -from DIR -to DIR -manifest URL [-enroll URL -code CODE]
                      [-report URL] [-system] [-no-autostart]
  installer uninstall [-system] [-purge]

  -from      directory holding the built %s and %s binaries
  -to        install directory
  -manifest  signed release manifest URL the agent will poll
  -enroll    fleet API enrollment endpoint
  -code      one-time enrollment code, issued by an administrator
  -report    fleet API events endpoint
  -system    install machine-wide (requires administrative rights)
`, layout.ShimName, layout.ProgramName)
	os.Exit(2)
}

type installOptions struct {
	from        string
	to          string
	manifestURL string
	enrollURL   string
	enrollCode  string
	reportURL   string
	system      bool
	noAutostart bool
}

func install(args []string) error {
	var o installOptions
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	fs.StringVar(&o.from, "from", ".", "directory holding the built binaries")
	fs.StringVar(&o.to, "to", defaultInstallDir(), "install directory")
	fs.StringVar(&o.manifestURL, "manifest", "", "signed release manifest URL")
	fs.StringVar(&o.enrollURL, "enroll", "", "fleet API enrollment endpoint")
	fs.StringVar(&o.enrollCode, "code", "", "one-time enrollment code")
	fs.StringVar(&o.reportURL, "report", "", "fleet API events endpoint")
	fs.BoolVar(&o.system, "system", false, "install machine-wide")
	fs.BoolVar(&o.noAutostart, "no-autostart", false, "place the binaries but do not register with the service manager")
	fs.Parse(args)

	if o.manifestURL == "" {
		return errors.New("-manifest is required; without it the agent cannot update")
	}

	paths, err := layout.For(o.to)
	if err != nil {
		return err
	}
	if err := paths.EnsureDataDir(); err != nil {
		return err
	}
	if err := os.MkdirAll(paths.InstallDir, 0o755); err != nil {
		return fmt.Errorf("create install directory: %w", err)
	}

	cfg := serviceConfig(paths, o)

	// Stop any existing service before replacing binaries. On Windows a running
	// image cannot be overwritten at all; elsewhere it merely avoids a needless
	// restart loop while files change underneath.
	_ = service.Uninstall(cfg)

	if err := placeBinaries(o.from, paths); err != nil {
		return err
	}
	if err := ensureIdentity(paths, o); err != nil {
		return err
	}
	// Registration is normally the point: without a service manager the program
	// exits after staging an update and nothing starts it again. The demo skips
	// it because it supplies its own supervisor, and two supervisors would
	// fight over the same process.
	if !o.noAutostart {
		if err := service.Install(cfg); err != nil {
			return fmt.Errorf("register service: %w", err)
		}
	}

	fmt.Printf("installed %s\n", installedVersion(paths))
	fmt.Printf("  install dir: %s\n", paths.InstallDir)
	fmt.Printf("  data dir:    %s\n", paths.DataDir)
	if o.noAutostart {
		fmt.Printf("  autostart:   skipped (-no-autostart)\n")
	} else {
		fmt.Printf("  autostart:   %s\n", service.Describe(cfg))
	}
	fmt.Printf("  channel:     %s\n", o.manifestURL)
	return nil
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	system := fs.Bool("system", false, "the install is machine-wide")
	dir := fs.String("from", defaultInstallDir(), "install directory")
	purge := fs.Bool("purge", false, "also delete state, events and the identity key")
	fs.Parse(args)

	paths, err := layout.For(*dir)
	if err != nil {
		return err
	}
	cfg := service.Config{Name: layout.AppName, Program: paths.Shim(), System: *system}

	if err := service.Uninstall(cfg); err != nil {
		return fmt.Errorf("deregister service: %w", err)
	}
	for _, path := range []string{paths.Shim(), paths.Program(), paths.BackupProgram(),
		paths.StagedProgram(), paths.StagingRecord()} {
		if err := fsutil.Remove(path); err != nil {
			return err
		}
	}

	if *purge {
		// Removing the identity means the install cannot be recovered — it has
		// to be re-enrolled with a fresh one-time code — so it is opt-in.
		if err := os.RemoveAll(paths.DataDir); err != nil {
			return fmt.Errorf("remove data directory: %w", err)
		}
	}
	fmt.Println("uninstalled")
	return nil
}

// placeBinaries copies the shim and the program into the install directory.
func placeBinaries(from string, paths layout.Layout) error {
	for _, item := range []struct{ src, dst string }{
		{filepath.Join(from, filepath.Base(paths.Shim())), paths.Shim()},
		{filepath.Join(from, filepath.Base(paths.Program())), paths.Program()},
	} {
		if !fsutil.Exists(item.src) {
			return fmt.Errorf("missing binary %s", item.src)
		}
		if err := fsutil.CopyFile(item.src, item.dst, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// ensureIdentity enrolls this install, or provisions a local identity when no
// enrollment endpoint is configured.
//
// Enrollment failure is fatal by design. An install with no identity produces
// telemetry nobody can trust and cannot be targeted for a rollout, and
// discovering that months later is worse than failing here where an
// administrator is watching.
func ensureIdentity(paths layout.Layout, o installOptions) error {
	if _, found, err := identity.Load(paths.IdentityFile()); err == nil && found {
		fmt.Println("  identity:    existing, reused")
		return nil
	}

	installID := state.NewInstallID()
	if o.enrollURL == "" {
		// Unenrolled: a locally generated ID still buckets this install for
		// staged rollout, which is all the update path needs. Only fleet
		// reporting is unavailable.
		if _, _, err := identity.Create(paths.IdentityFile(), installID); err != nil {
			return err
		}
		fmt.Println("  identity:    local (not enrolled; no fleet reporting)")
		return nil
	}

	if o.enrollCode == "" {
		return errors.New("-code is required when -enroll is set")
	}

	// The keypair is generated here and the private half never leaves this
	// machine. Only the public half is sent.
	tmpID, pub, err := identity.Create(paths.IdentityFile(), installID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	hostname, _ := os.Hostname()
	assigned, err := identity.Enroll(ctx, o.enrollURL, o.enrollCode, pub, identity.Machine{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  version.Version,
	})
	if err != nil {
		os.Remove(paths.IdentityFile())
		return fmt.Errorf("enrollment failed, install aborted: %w", err)
	}

	tmpID.InstallID = assigned
	if err := tmpID.Save(paths.IdentityFile()); err != nil {
		return err
	}
	fmt.Printf("  identity:    enrolled as %s\n", assigned)
	return nil
}

// installedVersion asks the program it just placed to identify itself.
//
// Reporting the installer's own version instead would be misleading: the
// installer and the program are built separately and the number people care
// about is the one now running on the machine.
func installedVersion(paths layout.Layout) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, paths.Program(), updater.SelfCheckFlag).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func serviceConfig(paths layout.Layout, o installOptions) service.Config {
	args := []string{"-manifest", o.manifestURL}
	env := []string{layout.EnvDataDir + "=" + paths.DataDir}
	if o.reportURL != "" {
		args = append(args, "-report-url", o.reportURL)
		env = append(env, "AGENT_REPORT_URL="+o.reportURL)
	}
	return service.Config{
		Name:    layout.AppName,
		Program: paths.Shim(),
		Args:    args,
		Env:     env,
		LogDir:  paths.DataDir,
		System:  o.system,
	}
}

func defaultInstallDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, layout.AppName, "bin")
		}
		return filepath.Join(home, "AppData", "Local", layout.AppName, "bin")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", layout.AppName, "bin")
	default:
		return filepath.Join(home, ".local", "bin", layout.AppName)
	}
}
