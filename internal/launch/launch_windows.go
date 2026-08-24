//go:build windows

package launch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// run starts the program as a child and waits for it.
//
// The shim must outlive the launch: the Service Control Manager watches the
// process it started, so exiting here would report the service as stopped while
// the program was still running. Waiting also makes the program's exit code the
// shim's, which lets a supervisor's restart policy see the program's behaviour
// rather than the shim's.
func run(path string, args, env []string) (int, error) {
	cmd := exec.Command(path, args[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start %s: %w", path, err)
	}

	err := cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("wait for %s: %w", path, err)
	}
	return 0, nil
}
