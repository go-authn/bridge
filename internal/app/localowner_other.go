// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package app

import "os"

// copyOwner does nothing where files have no Unix owner.
func copyOwner(*os.File, os.FileInfo) {}
