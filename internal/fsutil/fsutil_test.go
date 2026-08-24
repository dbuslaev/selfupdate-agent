package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomicReplacesContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("contents = %q, want %q", got, "second")
	}
}

// The temp file must land in the destination directory, or the rename crosses a
// filesystem boundary and silently degrades into a copy.
func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFileAtomic(filepath.Join(dir, "state.json"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Errorf("directory holds %d entries, want only the target", len(entries))
	}
}

func TestWriteFileAtomicHonoursPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "secret.json")
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 0600", got)
	}
}

func TestWriteFileAtomicCreatesMissingDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "state.json")
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Exists(path) {
		t.Error("the file was not created")
	}
}

func TestReadJSONFileDistinguishesAbsentFromUnreadable(t *testing.T) {
	dir := t.TempDir()

	_, found, err := ReadJSONFile(filepath.Join(dir, "missing.json"))
	if found || err != nil {
		t.Errorf("absent: found=%v err=%v, want false and nil", found, err)
	}

	path := filepath.Join(dir, "present.json")
	os.WriteFile(path, []byte("{}"), 0o600)
	body, found, err := ReadJSONFile(path)
	if !found || err != nil || string(body) != "{}" {
		t.Errorf("present: body=%q found=%v err=%v", body, found, err)
	}
}

func TestRemoveTreatsAbsentAsSuccess(t *testing.T) {
	if err := Remove(filepath.Join(t.TempDir(), "never-existed")); err != nil {
		t.Errorf("Remove on an absent path returned %v", err)
	}
}

func TestSHA256File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	digest, size, err := SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if digest != want {
		t.Errorf("digest = %s, want %s", digest, want)
	}
	if size != 5 {
		t.Errorf("size = %d, want 5", size)
	}
	if got := SHA256Bytes([]byte("hello")); got != want {
		t.Errorf("SHA256Bytes disagrees with SHA256File: %s", got)
	}
}

func TestFileModeFallsBack(t *testing.T) {
	if got := FileMode(filepath.Join(t.TempDir(), "missing"), 0o755); got != 0o755 {
		t.Errorf("FileMode on an absent path = %o, want the fallback", got)
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := CopyFile(src, dst, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("copied contents = %q", got)
	}
}
