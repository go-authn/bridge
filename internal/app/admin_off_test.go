// SPDX-License-Identifier: BSD-3-Clause

//go:build nogrpc

package app

import (
	"strings"
	"testing"
)

// A binary without gRPC refuses a configuration that asks for the admin
// API, rather than starting without it.
func TestAdminRefusedWithoutGRPC(t *testing.T) {
	c := newConf(t)
	if _, err := c.load(t, c.hcl(nil)+`admin { listen = "unix:///tmp/x.sock" }`); err == nil || !strings.Contains(err.Error(), "nogrpc") {
		t.Fatalf("err = %v", err)
	}
}
