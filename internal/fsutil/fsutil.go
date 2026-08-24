// Package fsutil holds the filesystem primitives the rest of the agent depends
// on for durability.
//
// Every helper here exists because a naive version of it loses data on a crash
// or a power cut. They are gathered in one place so that the durability
// reasoning lives in one file rather than being restated at each call site.
package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path so that a concurrent or subsequent reader
// sees either the previous contents or the new ones, never a partial write.
//
// The temporary file is created in the destination directory so the rename
// cannot cross a filesystem boundary, which would silently degrade it from an
// atomic operation into a copy.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("stage write in %s: %w", dir, err)
	}
	// Removing a path that the rename below has already consumed is harmless,
	// so this covers every error return without a flag to track success.
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmp.Name(), err)
	}
	// Flush before the rename. Without this a crash just afterwards can leave a
	// correctly named file full of zeroes.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename into %s: %w", path, err)
	}
	return SyncDir(dir)
}

// ReadJSONFile is a small convenience so callers can distinguish "absent" from
// "unreadable" without repeating the errors.Is dance.
func ReadJSONFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return b, true, nil
}

// Rename moves a file and persists the directory entry.
func Rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("rename %s to %s: %w", from, to, err)
	}
	return SyncDir(filepath.Dir(to))
}

// CopyFile duplicates src to dst, preserving permissions.
func CopyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("copy to %s: %w", dst, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("sync %s: %w", dst, err)
	}
	return out.Close()
}

// Remove deletes a path, treating "already gone" as success. Cleanup paths call
// this constantly and none of them care about the difference.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// Exists reports whether path is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SHA256File returns the lowercase hex digest and byte length of a file.
func SHA256File(path string) (digest string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// SHA256Bytes returns the lowercase hex digest of b.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileMode returns the permission bits of path, or fallback if it is missing.
// Used when replacing a binary, so an update cannot quietly widen access that
// an installer deliberately narrowed.
func FileMode(path string, fallback os.FileMode) os.FileMode {
	fi, err := os.Stat(path)
	if err != nil {
		return fallback
	}
	return fi.Mode().Perm()
}
