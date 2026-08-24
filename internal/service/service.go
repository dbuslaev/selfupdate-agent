// Package service registers the shim to start automatically.
//
// The unit of registration is always the shim, never the program. The shim owns
// the name that the supervisor, the service definition and any human refers to;
// the program behind it is an implementation detail that gets replaced.
//
// Registration is what makes the whole design work. The program exits when it
// has staged an update, and something outside the process tree has to bring it
// back — that something is launchd, systemd, or the Windows scheduler. Without
// a supervisor, an update stages and never installs.
package service

import (
	"fmt"
	"os/exec"
	"strings"
)

// Config describes the service to register.
type Config struct {
	// Name is the service identifier, used for the unit or job label.
	Name string
	// Program is the absolute path of the shim.
	Program string
	// Args are passed to the shim on every start.
	Args []string
	// Env is applied to the service, as KEY=VALUE.
	Env []string
	// LogDir is where stdout and stderr are written, where the platform needs
	// an explicit destination.
	LogDir string
	// System requests a machine-wide service rather than a per-user one. A
	// machine-wide service starts without anyone logged in and needs
	// administrative rights to install.
	System bool
}

// Install registers the service and starts it.
func Install(cfg Config) error { return install(cfg) }

// Uninstall stops the service and removes its registration.
func Uninstall(cfg Config) error { return uninstall(cfg) }

// Describe returns a human-readable summary of what Install will do, so the
// installer can print it before touching the system.
func Describe(cfg Config) string { return describe(cfg) }

// runCommand executes a helper such as systemctl or launchctl and folds its
// output into the error, because these tools report the useful detail on stderr
// and a bare exit status is close to useless when one fails.
func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, detail)
	}
	return nil
}
