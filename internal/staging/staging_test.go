package staging

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// install builds a directory holding a "binary" whose contents are its version
// string, plus a staged replacement, and returns a matching record.
func install(t *testing.T, current, staged string) (dir string, r Record) {
	t.Helper()
	dir = t.TempDir()

	target := filepath.Join(dir, "agent-app")
	stagedPath := target + ".staged"
	write(t, target, current, 0o755)
	write(t, stagedPath, staged, 0o755)

	digest, _, err := fsutil.SHA256File(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	return dir, Record{
		Target:      target,
		Staged:      stagedPath,
		Version:     staged,
		FromVersion: current,
		SHA256:      digest,
	}
}

func TestApplyInstallsAndKeepsABackup(t *testing.T) {
	dir, record := install(t, "1.0.0", "1.1.0")
	backup := filepath.Join(dir, "agent-app.prev")

	if err := Apply(record, backup); err != nil {
		t.Fatal(err)
	}

	if got := read(t, record.Target); got != "1.1.0" {
		t.Errorf("target holds %q, want the new version", got)
	}
	if got := read(t, backup); got != "1.0.0" {
		t.Errorf("backup holds %q, want the outgoing version", got)
	}
	// The staged file must be consumed rather than copied, or every update
	// leaves a full-size temp file in the install directory.
	if fsutil.Exists(record.Staged) {
		t.Error("the staged file still exists after installation")
	}
}

// The digest check is what stops anyone with write access to the install
// directory from getting code execution at the next start by dropping a file
// with the expected name.
func TestApplyRefusesAMismatchedDigest(t *testing.T) {
	dir, record := install(t, "1.0.0", "1.1.0")
	write(t, record.Staged, "something else entirely", 0o755)

	if err := Apply(record, filepath.Join(dir, "agent-app.prev")); err == nil {
		t.Fatal("Apply installed a binary that did not match its record")
	}
	if got := read(t, record.Target); got != "1.0.0" {
		t.Errorf("target holds %q; a refused update must leave the install untouched", got)
	}
}

func TestApplyCarriesPermissionsForward(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	dir, record := install(t, "1.0.0", "1.1.0")

	// An installer may deliberately have narrowed access; an update must not
	// quietly widen it.
	if err := os.Chmod(record.Target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(record.Staged, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := Apply(record, filepath.Join(dir, "agent-app.prev")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(record.Target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("permissions after installation = %o, want 0700 carried from the original", got)
	}
}

func TestRestoreUndoesApply(t *testing.T) {
	dir, record := install(t, "1.0.0", "1.1.0")
	backup := filepath.Join(dir, "agent-app.prev")

	if err := Apply(record, backup); err != nil {
		t.Fatal(err)
	}
	if err := Restore(record.Target, backup); err != nil {
		t.Fatal(err)
	}

	if got := read(t, record.Target); got != "1.0.0" {
		t.Errorf("target holds %q after restore, want the previous version", got)
	}
	if fsutil.Exists(backup) {
		t.Error("the backup should be consumed by a restore")
	}
}

func TestRestoreReportsAMissingBackup(t *testing.T) {
	dir, record := install(t, "1.0.0", "1.1.0")

	if err := Restore(record.Target, filepath.Join(dir, "nonexistent")); err == nil {
		t.Fatal("Restore succeeded with no backup present")
	}
}

func TestRecordRoundTrip(t *testing.T) {
	dir, record := install(t, "1.0.0", "1.1.0")
	path := filepath.Join(dir, "staging.json")

	if err := Write(path, record); err != nil {
		t.Fatal(err)
	}
	got, found, err := Read(path)
	if err != nil || !found {
		t.Fatalf("Read = %v, found=%v", err, found)
	}
	if got.Version != record.Version || got.SHA256 != record.SHA256 || got.Target != record.Target {
		t.Errorf("round trip lost data: %+v", got)
	}

	if err := Clear(path, got); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := Read(path); found {
		t.Error("Clear left the record behind")
	}
}

func TestReadReportsAbsentAndMalformedRecordsDifferently(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "staging.json")

	if _, found, err := Read(path); found || err != nil {
		t.Errorf("absent record: found=%v err=%v, want false and nil", found, err)
	}

	// A record we cannot parse means we cannot know what the staged file is,
	// and a binary we cannot describe must never be installed.
	write(t, path, "{not json", 0o644)
	if _, found, err := Read(path); found || err == nil {
		t.Errorf("malformed record: found=%v err=%v, want false and an error", found, err)
	}

	write(t, path, `{"target":"x"}`, 0o644)
	if _, found, err := Read(path); found || err == nil {
		t.Errorf("incomplete record: found=%v err=%v, want false and an error", found, err)
	}
}

func TestVerifyDetectsASubstitutedFile(t *testing.T) {
	_, record := install(t, "1.0.0", "1.1.0")
	if err := record.Verify(); err != nil {
		t.Fatalf("a matching staged file failed verification: %v", err)
	}

	write(t, record.Staged, strings.Repeat("x", 64), 0o755)
	if err := record.Verify(); err == nil {
		t.Fatal("Verify accepted a substituted staged file")
	}
}

func write(t *testing.T, path, contents string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), perm); err != nil {
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
