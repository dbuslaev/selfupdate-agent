// Package launch hands control from the shim to the program.
//
// This is the only place where the supported platforms genuinely differ, and
// the difference is structural rather than cosmetic. On Unix the shim replaces
// its own process image and ceases to exist. On Windows there is no equivalent,
// so the shim spawns a child and stays alive waiting on it, because the Service
// Control Manager tracks the process it launched: if the shim exited, the
// service would be considered stopped.
//
// That has a consequence worth knowing. On Unix the shim binary is not held open
// once it has exec'd; on Windows it is, for the whole life of the program. The
// asymmetry is one reason the shim is never replaced in place at all — a release
// that changes it is marked requires_reinstall instead.
package launch

// Program starts the program binary with args (argv[0] included) and env.
//
// On Unix it does not return on success. On Windows it returns once the child
// exits, yielding the child's exit code.
func Program(path string, args, env []string) (exitCode int, err error) {
	return run(path, args, env)
}
