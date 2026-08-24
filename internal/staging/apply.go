package staging

import (
	"fmt"
	"os"

	"github.com/dbuslaev/selfupdate-agent/internal/fsutil"
)

// Apply installs a staged binary, keeping the outgoing one as a backup.
//
// This is deliberately platform-independent, and that is the payoff of the shim
// design. The target is not running when this executes, so nothing holds the
// file open: two ordinary renames work the same way on Unix and Windows. An
// in-process updater cannot do this — Windows forbids overwriting a running
// image, which forces a different sequence and leaves a window in which the
// target path does not exist.
//
// Order matters. The current binary is moved aside first, so that if the second
// rename fails the original can be put back and the install is left exactly as
// it was.
func Apply(r Record, backupPath string) error {
	if err := r.Verify(); err != nil {
		return err
	}
	// Carry the outgoing permission bits forward. An installer may have chosen
	// something other than 0755 — setgid for a shared install, 0700 for a
	// per-user one — and an update must not quietly widen access.
	mode := fsutil.FileMode(r.Target, 0o755)
	if err := os.Chmod(r.Staged, mode); err != nil {
		return fmt.Errorf("set permissions on staged binary: %w", err)
	}

	if err := fsutil.Remove(backupPath); err != nil {
		return err
	}
	if fsutil.Exists(r.Target) {
		if err := fsutil.Rename(r.Target, backupPath); err != nil {
			return fmt.Errorf("move current binary aside: %w", err)
		}
	}

	if err := fsutil.Rename(r.Staged, r.Target); err != nil {
		// Put the original back. A failed update must leave a working install.
		if restoreErr := fsutil.Rename(backupPath, r.Target); restoreErr != nil {
			return fmt.Errorf("install staged binary: %w; RESTORE ALSO FAILED, "+
				"the previous binary is at %s and must be moved back by hand: %v",
				err, backupPath, restoreErr)
		}
		return fmt.Errorf("install staged binary: %w", err)
	}
	return nil
}

// Restore puts the backup back, undoing a previous Apply.
func Restore(target, backupPath string) error {
	if !fsutil.Exists(backupPath) {
		return fmt.Errorf("no backup at %s to restore", backupPath)
	}
	// The target is the binary that failed. It is not running at this point —
	// the shim performs restores before launching anything — so it can be
	// removed outright.
	if err := fsutil.Remove(target); err != nil {
		return fmt.Errorf("remove failed binary: %w", err)
	}
	if err := fsutil.Rename(backupPath, target); err != nil {
		return fmt.Errorf("restore backup: %w", err)
	}
	return nil
}
