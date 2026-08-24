package main

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/dbuslaev/selfupdate-agent/internal/updater"
)

// selfCheckTimeout bounds the version query. The shim is on the startup path,
// so a program that hangs on --self-check must not hang the boot.
const selfCheckTimeout = 5 * time.Second

// runSelfCheck asks a binary to print its version.
//
// This is the same contract the program uses to vet a candidate before staging
// it, reused here so there is one definition of "identify yourself" rather than
// two that can drift apart.
func runSelfCheck(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), selfCheckTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, updater.SelfCheckFlag).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
