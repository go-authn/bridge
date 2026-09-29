// SPDX-License-Identifier: BSD-3-Clause

//go:build nogrpc

package main

import "context"

// Built with -tags nogrpc: no admin API, and a configuration that asks for
// one is refused at start (see config.check) rather than started without it.

const haveGRPC = false

func (s *server) openAdmin() (func(context.Context) error, error) { return nil, nil }

func checkAdmin(*adminBlock) error { return nil }
