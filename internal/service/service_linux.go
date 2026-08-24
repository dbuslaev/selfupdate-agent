//go:build linux

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// unitTemplate is a systemd service.
//
// Restart=always is required, not stylistic. The program exits 0 when it has
// staged an update, and Restart=on-failure would leave it stopped — the client
// would be dead until someone rebooted it. RestartPreventExitStatus carves out
// the one exit that genuinely should not be retried: a build below the minimum
// supported version, which needs an administrator rather than another attempt.
const unitTemplate = `[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
%s
Restart=always
RestartSec=5s
# Exit code 2 means "this build is no longer supported"; retrying cannot fix it.
RestartPreventExitStatus=2

[Install]
WantedBy=%s
`

func install(cfg Config) error {
	unit := fmt.Sprintf(unitTemplate,
		cfg.Name,
		commandLine(cfg),
		environmentLines(cfg.Env),
		wantedBy(cfg.System),
	)

	path, err := unitPath(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create unit directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit %s: %w", path, err)
	}

	args := systemctlScope(cfg.System)
	if err := runCommand("systemctl", append(args, "daemon-reload")...); err != nil {
		return err
	}
	return runCommand("systemctl", append(args, "enable", "--now", cfg.Name+".service")...)
}

func uninstall(cfg Config) error {
	args := systemctlScope(cfg.System)
	// Ignore failures here: the point is to reach "not installed", and a unit
	// that is already stopped or already absent is not an error.
	_ = runCommand("systemctl", append(args, "disable", "--now", cfg.Name+".service")...)

	path, err := unitPath(cfg)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit %s: %w", path, err)
	}
	return runCommand("systemctl", append(args, "daemon-reload")...)
}

func describe(cfg Config) string {
	path, err := unitPath(cfg)
	if err != nil {
		path = "(unresolved)"
	}
	return fmt.Sprintf("systemd unit %s, enabled with systemctl %s",
		path, strings.Join(systemctlScope(cfg.System), " "))
}

func unitPath(cfg Config) (string, error) {
	if cfg.System {
		return filepath.Join("/etc/systemd/system", cfg.Name+".service"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", cfg.Name+".service"), nil
}

func systemctlScope(system bool) []string {
	if system {
		return nil
	}
	return []string{"--user"}
}

func wantedBy(system bool) string {
	if system {
		return "multi-user.target"
	}
	return "default.target"
}

func commandLine(cfg Config) string {
	return strings.Join(append([]string{cfg.Program}, cfg.Args...), " ")
}

func environmentLines(env []string) string {
	var b strings.Builder
	for _, kv := range env {
		fmt.Fprintf(&b, "Environment=%q\n", kv)
	}
	return strings.TrimRight(b.String(), "\n")
}
