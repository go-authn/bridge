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
	return readSecretFileAs(path, limit, os.Geteuid())
}

// readSecretFileAs is readSecretFile for a service running as uid.
func readSecretFileAs(path string, limit int64, uid int) ([]byte, error) {
	f, err := os.Open(path)
	var b []byte
	if err == nil {
		defer f.Close()
		b, err = readOpenSecret(f, limit, uid)
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// readOpenSecret judges the descriptor, then reads it, in that order and on that
// descriptor. Any error from the open or the stat or the read ends in the one
// refusal of the caller.
func readOpenSecret(f *os.File, limit int64, uid int) ([]byte, error) {
	fi, err := f.Stat()
	if err == nil {
		err = judgeSecret(fi, uid)
	}
	var b []byte
	if err == nil {
		b, err = io.ReadAll(io.LimitReader(f, limit+1))
	}
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("larger than %d bytes", limit)
	}
	return b, err
}

func judgeSecret(fi os.FileInfo, uid int) error {
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if p := fi.Mode().Perm(); p&0o077 != 0 {
		return fmt.Errorf("mode %04o: readable by group or others; chmod 0600", p)
	}
	// On a unix build os.File.Stat always carries a *syscall.Stat_t.
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != uid {
		return fmt.Errorf("owned by uid %d, not by the service user (uid %d)", st.Uid, uid)
	}
	return nil
}
