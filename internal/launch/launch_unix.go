//go:build unix

package launch

import (
	"fmt"
	"syscall"
)

// run replaces the shim's process image with the program.
//
// execve keeps the pid, the open file descriptors and the parent relationship,
// so a supervisor sees one continuous process rather than a shim that exited
// and a program that appeared. It also means the shim costs nothing in memory
// or process count once the program is running.
//
// It returns only on failure.
func run(path string, args, env []string) (int, error) {
	if err := syscall.Exec(path, args, env); err != nil {
		return 1, fmt.Errorf("exec %s: %w", path, err)
	}
	return 0, nil // unreachable
}
