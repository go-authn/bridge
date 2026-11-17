// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package app

import (
	"os"
	"syscall"
)

// copyOwner gives f the owner and group of the file it will replace. Best
// effort: only root can give a file to somebody else, and a refusal leaves the
// file the invoking user's, which the provider's mode check still accepts.
func copyOwner(f *os.File, like os.FileInfo) {
	if st, ok := like.Sys().(*syscall.Stat_t); ok {
		_ = f.Chown(int(st.Uid), int(st.Gid))
	}
}
