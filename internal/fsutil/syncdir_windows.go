//go:build windows

package fsutil

// SyncDir is a no-op on Windows: directories cannot be opened as files, and
// NTFS metadata journalling already covers the ordering guarantee that fsync on
// a directory provides elsewhere.
func SyncDir(string) error { return nil }
