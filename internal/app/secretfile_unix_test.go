// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package app

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecretFileRefusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := readSecretFile(filepath.Join(dir, "absent"), 100); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v, want ErrNotExist", err)
	}
	sub := filepath.Join(dir, "d")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(sub, 100); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	p := filepath.Join(dir, "s")
	if err := os.WriteFile(p, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readSecretFileAs(p, 100, os.Geteuid()); err != nil || string(b) != "pw\n" {
		t.Errorf("the service user's own file: %q %v", b, err)
	}
	if _, err := readSecretFileAs(p, 100, os.Geteuid()+1); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("another owner: %v", err)
	}
}
