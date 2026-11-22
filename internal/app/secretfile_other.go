// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// readSecretFile reads a secret from a file with one open. This platform has no
// owner or mode bits to check (the bridge is deployed on Unix: docs/install.md);
// the access list of the file is the operator's.
func readSecretFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
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
