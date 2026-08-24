package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/dbuslaev/selfupdate-agent/internal/events"
	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
	"github.com/dbuslaev/selfupdate-agent/internal/layout"
	"github.com/dbuslaev/selfupdate-agent/internal/staging"
	"github.com/dbuslaev/selfupdate-agent/internal/state"
)

// install builds a fake installation whose "binaries" are files containing
// their own version string, so a swap is observable by reading them.
func install(t *testing.T, current string) (layout.Layout, *state.State, *events.Log) {
	t.Helper()
	root := t.TempDir()

	paths := layout.Layout{
		InstallDir: filepath.Join(root, "bin"),
		DataDir:    filepath.Join(root, "data"),
	}
	for _, dir := range []string{paths.InstallDir, paths.DataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths.Program(), []byte(current), 0o755); err != nil {
		t.Fatal(err)
	}

	st := state.New()
	st.LastCommitted = current
	return paths, st, events.NewLog(paths.EventLog(), "shim-test")
}

// stage writes a staged binary and its record, as the program would.
func stage(t *testing.T, paths layout.Layout, from, to string) {
	t.Helper()

	stagedPath := paths.StagedProgram()
	if err := os.WriteFile(stagedPath, []byte(to), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, _, err := fsutil.SHA256File(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	err = staging.Write(paths.StagingRecord(), staging.Record{
		Target:      paths.Program(),
		Staged:      stagedPath,
		Version:     to,
		FromVersion: from,
		SHA256:      digest,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestInstallStagedProgramSwapsAndBeginsTrial(t *testing.T) {
	paths, st, log := install(t, "1.0.0")
	stage(t, paths, "1.0.0", "1.1.0")

	installStagedProgram(quietLogger(), paths, st, log)

	if got := read(t, paths.Program()); got != "1.1.0" {
		t.Errorf("program is %q, want the staged version installed", got)
	}
	if got := read(t, paths.BackupProgram()); got != "1.0.0" {
		t.Errorf("backup is %q, want the outgoing version retained", got)
	}
	if st.PendingVersion != "1.1.0" || st.PreviousVersion != "1.0.0" || st.BootAttempts != 0 {
		t.Errorf("trial not started correctly: %+v", st)
	}
	// The record and staged file must be consumed, or the next start would try
	// to install the same update again.
	if fsutil.Exists(paths.StagingRecord()) || fsutil.Exists(paths.StagedProgram()) {
		t.Error("the staging record or staged file survived installation")
	}
}

// The digest check is what stops anyone with write access to the install
// directory from getting code execution at the next start.
func TestInstallStagedProgramRefusesASubstitutedBinary(t *testing.T) {
	paths, st, log := install(t, "1.0.0")
	stage(t, paths, "1.0.0", "1.1.0")

	// Someone replaces the staged file after the program verified it.
	if err := os.WriteFile(paths.StagedProgram(), []byte("malicious"), 0o755); err != nil {
		t.Fatal(err)
	}

	installStagedProgram(quietLogger(), paths, st, log)

	if got := read(t, paths.Program()); got != "1.0.0" {
		t.Errorf("program is %q; a refused install must leave the original in place", got)
	}
	if st.OnTrial() {
		t.Error("no trial should start when nothing was installed")
	}
	if !st.IsPoisoned("1.1.0") {
		t.Error("the failed version should be poisoned so it is not fetched again")
	}
}

func TestInstallStagedProgramDiscardsACorruptRecord(t *testing.T) {
	paths, st, log := install(t, "1.0.0")
	if err := os.WriteFile(paths.StagingRecord(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StagedProgram(), []byte("1.1.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	installStagedProgram(quietLogger(), paths, st, log)

	// A binary we cannot describe must never be installed, and must not be left
	// lying around to be picked up later.
	if got := read(t, paths.Program()); got != "1.0.0" {
		t.Errorf("program is %q, want the original untouched", got)
	}
	if fsutil.Exists(paths.StagedProgram()) || fsutil.Exists(paths.StagingRecord()) {
		t.Error("an undescribable staged binary should be discarded")
	}
}

func TestResolveTrialCountsBootsWithinBudget(t *testing.T) {
	paths, st, log := install(t, "1.1.0")
	st.BeginTrial("1.1.0", "1.0.0")
	writeBackup(t, paths, "1.0.0")

	for attempt := 1; attempt <= maxBootAttempts; attempt++ {
		resolveTrial(quietLogger(), paths, st, log)

		if st.BootAttempts != attempt {
			t.Fatalf("after boot %d, attempts = %d", attempt, st.BootAttempts)
		}
		if got := read(t, paths.Program()); got != "1.1.0" {
			t.Fatalf("boot %d rolled back early; program is %q", attempt, got)
		}
	}
}

// The reason boot counting lives in the shim: a build that dies during
// initialisation never counts itself, but the shim runs on every start.
func TestResolveTrialRollsBackPastBudget(t *testing.T) {
	paths, st, log := install(t, "1.1.0")
	st.BeginTrial("1.1.0", "1.0.0")
	writeBackup(t, paths, "1.0.0")

	for i := 0; i <= maxBootAttempts; i++ {
		resolveTrial(quietLogger(), paths, st, log)
	}

	if got := read(t, paths.Program()); got != "1.0.0" {
		t.Errorf("program is %q, want the previous version restored", got)
	}
	if st.OnTrial() {
		t.Error("the trial must be cleared, or the restored binary counts its own boots and rolls back to itself")
	}
	if !st.IsPoisoned("1.1.0") {
		t.Error("the failed version must be poisoned, or it is downloaded and installed again immediately")
	}
	if st.LastCommitted != "1.0.0" {
		t.Errorf("last committed = %q, want the restored version", st.LastCommitted)
	}
}

// A rollback with no usable backup must not stop the agent from starting: a
// crashing program still reports, and an operator needs the machine reachable.
func TestResolveTrialSurvivesAMissingBackup(t *testing.T) {
	paths, st, log := install(t, "1.1.0")
	st.BeginTrial("1.1.0", "1.0.0")
	// Deliberately no backup written.

	for i := 0; i <= maxBootAttempts; i++ {
		resolveTrial(quietLogger(), paths, st, log)
	}

	if got := read(t, paths.Program()); got != "1.1.0" {
		t.Errorf("program is %q; with no backup the failing binary should remain", got)
	}
}

func TestResolveTrialIsANoOpWhenNothingIsPending(t *testing.T) {
	paths, st, log := install(t, "1.0.0")

	resolveTrial(quietLogger(), paths, st, log)

	if st.BootAttempts != 0 {
		t.Errorf("attempts = %d, want no counting outside a trial", st.BootAttempts)
	}
}

// The shim forwards every argument to the program, so it must recognise its own
// one flag without parsing the rest.
func TestHasArgAcceptsBothSpellings(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()

	os.Args = []string{"agent", "-manifest", "https://example.com", "--self-check"}
	if !hasArg("--self-check") {
		t.Error("hasArg missed the double-dash spelling")
	}

	os.Args = []string{"agent", "-self-check"}
	if !hasArg("--self-check") {
		t.Error("hasArg missed the single-dash spelling")
	}

	os.Args = []string{"agent", "-manifest", "https://example.com"}
	if hasArg("--self-check") {
		t.Error("hasArg matched an argument that was not present")
	}
}

func writeBackup(t *testing.T, paths layout.Layout, version string) {
	t.Helper()
	if err := os.WriteFile(paths.BackupProgram(), []byte(version), 0o755); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
