// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readSecretFile reads a secret from a file with ONE open: the checks and the
// read are on the same descriptor, so the file cannot be swapped between them.
// The file must be a regular file, owned by the user the service runs as, and
// not accessible to group or others (mode 0600 or 0400).
func readSecretFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if p := fi.Mode().Perm(); p&0o077 != 0 {
		return nil, fmt.Errorf("mode %04o: readable by group or others; chmod 0600", p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("the owner cannot be read")
	}
	if int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("owned by uid %d, not by the service user (uid %d)", st.Uid, os.Geteuid())
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}
