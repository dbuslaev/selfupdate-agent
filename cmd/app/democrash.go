//go:build democrash

package main

import (
	"fmt"
	"os"
	"time"
)

// This file is only compiled with `-tags democrash`. It builds a program that
// starts normally and then dies before it can report healthy, so the demo can
// show automatic rollback without waiting for a real bug.
//
// It is kept behind a build tag rather than a flag deliberately: a normal
// release must have no code path that can be talked into crashing on purpose.
func init() {
	go func() {
		time.Sleep(2 * time.Second)
		fmt.Fprintln(os.Stderr, "democrash: exiting before the health timer fires")
		os.Exit(1)
	}()
}
