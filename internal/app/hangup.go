// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"os"
	"os/signal"
	"syscall"
)

// ignoreHangup catches SIGHUP and says so, until stop is called.
//
// ⛔ The provider does not reload its configuration. Left to Go's default, a
// SIGHUP -- `systemctl reload`, logrotate's postrotate, a `kill -HUP` out of
// habit -- KILLS it, and systemd counts death by SIGHUP as a clean exit:
// Restart=on-failure does not restart it, and the unit goes inactive with
// Result=success (measured with go-authn/authnd, which had the same gap).
// So it stays up and logs that a configuration change needs a restart.
func ignoreHangup(logf func(string, ...any)) (stop func()) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-hup:
				logf("SIGHUP: ignored, nothing is reloaded; restart the service to apply a configuration change (TLS certificate files are re-read on their own)")
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(hup)
		close(done)
	}
}
