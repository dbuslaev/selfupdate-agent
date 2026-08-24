//go:build windows

package service

import (
	"fmt"
	"strings"
)

// Windows registration uses the Task Scheduler.
//
// A scheduled task provides what the agent needs — start at boot or logon,
// restart on failure, no console window — with no third-party dependency. The
// visible trade-off is that it does not appear in services.msc, and start and
// stop go through schtasks. See docs/OPERATIONS.md.
//
// Registering a true Windows service instead would change only this file.
func install(cfg Config) error {
	trigger, runLevel := "ONSTART", "HIGHEST"
	if !cfg.System {
		trigger, runLevel = "ONLOGON", "LIMITED"
	}

	args := []string{
		"/Create",
		"/TN", cfg.Name,
		"/TR", quotedCommand(cfg),
		"/SC", trigger,
		"/RL", runLevel,
		"/F", // replace an existing task, so reinstall is idempotent
	}
	if cfg.System {
		args = append(args, "/RU", "SYSTEM")
	}

	if err := runCommand("schtasks", args...); err != nil {
		return err
	}
	return runCommand("schtasks", "/Run", "/TN", cfg.Name)
}

func uninstall(cfg Config) error {
	_ = runCommand("schtasks", "/End", "/TN", cfg.Name)
	return runCommand("schtasks", "/Delete", "/TN", cfg.Name, "/F")
}

func describe(cfg Config) string {
	scope := "at logon, as the current user"
	if cfg.System {
		scope = "at boot, as SYSTEM"
	}
	return fmt.Sprintf("scheduled task %q, starting %s", cfg.Name, scope)
}

// quotedCommand builds the /TR value.
//
// schtasks passes this to the shell, and install paths routinely contain
// spaces, so the executable is quoted. Environment is supplied on the command
// line rather than as task properties, because the Task Scheduler has no
// per-task environment block.
func quotedCommand(cfg Config) string {
	parts := []string{`"` + cfg.Program + `"`}
	parts = append(parts, cfg.Args...)
	return strings.Join(parts, " ")
}
