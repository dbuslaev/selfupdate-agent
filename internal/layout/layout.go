// Package layout names every file the agent touches and decides where it lives.
//
// There are two directories, and the split matters:
//
//   - The install directory holds executables. On a system-wide install it is
//     often owned by an installer and may be read-only to the service account.
//   - The data directory holds mutable state, the event log and the identity
//     key. It is always writable by the account the agent runs as.
//
// Putting state next to the binary is convenient for a demo and wrong for a
// real install, so the two are separated from the start.
package layout

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Names of the two executables. The shim owns the name that supervisors,
// service definitions and humans refer to; the program it launches sits beside
// it under a second name and is an implementation detail.
const (
	AppName     = "selfupdate-agent"
	ShimName    = "agent"
	ProgramName = "agent-app"
)

// Environment overrides, mainly so the demo can run several installs side by
// side without touching the real user directories.
const (
	EnvInstallDir = "AGENT_INSTALL_DIR"
	EnvDataDir    = "AGENT_DATA_DIR"
)

// Layout resolves paths for one installation.
type Layout struct {
	InstallDir string
	DataDir    string
}

// Resolve derives the layout from the running executable, with environment
// overrides taking precedence.
//
// Symlinks are resolved so that an install exposed as /usr/local/bin/agent ->
// /opt/agent/agent is operated on at its real location. Replacing the symlink
// instead would orphan the install directory.
func Resolve() (Layout, error) {
	exe, err := os.Executable()
	if err != nil {
		return Layout{}, fmt.Errorf("locate own binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return For(filepath.Dir(exe))
}

// For builds a layout rooted at an explicit install directory. The installer
// uses this before anything has been installed.
func For(installDir string) (Layout, error) {
	if override := os.Getenv(EnvInstallDir); override != "" {
		installDir = override
	}
	dataDir, err := defaultDataDir()
	if err != nil {
		return Layout{}, err
	}
	return Layout{InstallDir: installDir, DataDir: dataDir}, nil
}

// Executables. Callers never build these names by hand, so the .exe suffix is
// handled in exactly one place.

// Shim is the binary a supervisor launches.
func (l Layout) Shim() string { return filepath.Join(l.InstallDir, exeName(ShimName)) }

// Program is the binary the shim executes.
func (l Layout) Program() string { return filepath.Join(l.InstallDir, exeName(ProgramName)) }

// StagedProgram is a downloaded, verified program awaiting the next start.
func (l Layout) StagedProgram() string { return l.Program() + ".staged" }

// BackupProgram is the previous program, retained until the new one commits.
func (l Layout) BackupProgram() string { return l.Program() + ".prev" }

// Data files.

// StagingRecord describes a staged binary. It lives in the install directory
// beside the file it describes, because the two are written and consumed as a
// pair and both require install-directory access anyway.
func (l Layout) StagingRecord() string { return filepath.Join(l.InstallDir, "staging.json") }

// StateFile holds update state: pending version, boot attempts, poisoned list.
func (l Layout) StateFile() string { return filepath.Join(l.DataDir, "state.json") }

// EventLog is the append-only queue of events awaiting delivery.
func (l Layout) EventLog() string { return filepath.Join(l.DataDir, "events.jsonl") }

// IdentityFile holds the install ID and the private key used to sign requests.
func (l Layout) IdentityFile() string { return filepath.Join(l.DataDir, "identity.json") }

// EnsureDataDir creates the data directory with owner-only permissions, since
// it holds the private key.
func (l Layout) EnsureDataDir() error {
	if err := os.MkdirAll(l.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory %s: %w", l.DataDir, err)
	}
	return nil
}

// Writable reports whether the install directory can be modified by this
// process. Checked before a download rather than after, so that a
// package-manager-owned or read-only install fails with a clear message instead
// of an obscure permission error partway through.
func (l Layout) Writable() error {
	probe, err := os.CreateTemp(l.InstallDir, ".probe-*")
	if err != nil {
		return fmt.Errorf("install directory %s is not writable by this process: %w", l.InstallDir, err)
	}
	name := probe.Name()
	probe.Close()
	return os.Remove(name)
}

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

// defaultDataDir picks the conventional per-user state directory for the
// platform. A system-wide install overrides it via AGENT_DATA_DIR, because a
// service account may have no home directory at all.
func defaultDataDir() (string, error) {
	if override := os.Getenv(EnvDataDir); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, AppName), nil
		}
		return filepath.Join(home, "AppData", "Local", AppName), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", AppName), nil
	default:
		if base := os.Getenv("XDG_STATE_HOME"); base != "" {
			return filepath.Join(base, AppName), nil
		}
		return filepath.Join(home, ".local", "state", AppName), nil
	}
}
