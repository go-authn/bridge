// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package app

import (
	"fmt"
	"syscall"
	"testing"
	"time"
)

// A REAL SIGHUP, to this test process: without the handler, Go's default
// kills the test binary ("signal: hangup") and the package fails.
func TestASighupDoesNotKillTheProvider(t *testing.T) {
	logged := make(chan string, 4)
	stop := ignoreHangup(func(format string, a ...any) { logged <- fmt.Sprintf(format, a...) })
	defer stop()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-logged:
		t.Log(line)
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP was not caught")
	}
}
