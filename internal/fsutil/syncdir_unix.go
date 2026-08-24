//go:build unix

package fsutil

import "os"

// SyncDir flushes a directory entry to stable storage, so that a rename into it
// survives a power cut. Without this the file contents can be durable while the
// name that points at them is not.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
