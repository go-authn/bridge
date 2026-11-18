// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tgzOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for n, c := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(c))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestParseNames(t *testing.T) {
	got, err := parseNames(strings.NewReader("# comment\n\nkey-round\n  check  \ntrash-2\n"))
	if err != nil || strings.Join(got, ",") != "key-round,check,trash-2" {
		t.Errorf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", "# only a comment\n", "Key\n", "a b\n", "../x\n", "x\nx\n"} {
		if _, err := parseNames(strings.NewReader(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := iconNames(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("a missing icons.txt was accepted")
	}
	f := filepath.Join(t.TempDir(), "icons.txt")
	os.WriteFile(f, []byte("check\n"), 0o644)
	if n, err := iconNames(f); err != nil || len(n) != 1 {
		t.Errorf("iconNames: %v %v", n, err)
	}
}

func TestVerify(t *testing.T) {
	b := []byte("tailwind")
	h := sha256.Sum256(b)
	if err := verifySHA256(b, hex.EncodeToString(h[:])); err != nil {
		t.Error(err)
	}
	if err := verifySHA256(b, strings.Repeat("0", 64)); err == nil {
		t.Error("a wrong sha256 was accepted")
	}
	if err := verifySHA256(b, ""); err == nil {
		t.Error("no pinned sha256 was accepted")
	}
	s := sha512.Sum512(b)
	if err := verifySRI(b, base64.StdEncoding.EncodeToString(s[:])); err != nil {
		t.Error(err)
	}
	if err := verifySRI(append(b, '!'), base64.StdEncoding.EncodeToString(s[:])); err == nil {
		t.Error("a wrong sha512 was accepted")
	}
}

func TestPinsCoverEveryPlatformWeRun(t *testing.T) {
	for _, p := range []string{"linux-x64", "linux-arm64", "macos-arm64", "macos-x64", "windows-x64"} {
		if len(tailwindSums[p]) != 64 {
			t.Errorf("no sha256 pinned for %s", p)
		}
	}
	if len(lucideIntegrity) != 88 {
		t.Errorf("the lucide integrity is %d characters, not a base64 sha512", len(lucideIntegrity))
	}
	if _, err := platform(); err != nil {
		t.Logf("this platform has no CLI: %v", err)
	}
}

func TestExtractIcons(t *testing.T) {
	tgz := tgzOf(t, map[string]string{
		"package/icons/check.svg":   "<svg>c</svg>",
		"package/icons/other.svg":   "<svg>o</svg>",
		"package/LICENSE":           "ISC",
		"package/icons/../evil.svg": "<svg>e</svg>",
	})
	icons, lic, err := extractIcons(tgz, []string{"check"})
	if err != nil || string(icons["check"]) != "<svg>c</svg>" || len(icons) != 1 || string(lic) != "ISC" {
		t.Errorf("got %v %q %v", icons, lic, err)
	}
	if _, _, err := extractIcons(tgz, []string{"missing"}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("a missing icon: %v", err)
	}
	if _, _, err := extractIcons(tgzOf(t, map[string]string{"package/icons/check.svg": "x"}), []string{"check"}); err == nil {
		t.Error("a release without a LICENSE was accepted")
	}
	if _, _, err := extractIcons([]byte("not gzip"), nil); err == nil {
		t.Error("garbage was accepted")
	}
	var bad bytes.Buffer
	zw := gzip.NewWriter(&bad)
	zw.Write([]byte("not a tar archive, but long enough to be read as a header block: " + strings.Repeat("x", 600)))
	zw.Close()
	if _, _, err := extractIcons(bad.Bytes(), nil); err == nil {
		t.Error("a bad tar was accepted")
	}
}

func TestFetchVerifiesBeforeCaching(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/gone" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "payload")
	}))
	defer srv.Close()
	h := sha256.Sum256([]byte("payload"))
	good := func(b []byte) error { return verifySHA256(b, hex.EncodeToString(h[:])) }
	bad := func(b []byte) error { return verifySHA256(b, strings.Repeat("0", 64)) }
	cached := filepath.Join(t.TempDir(), "bin")

	if _, err := fetch(srv.URL+"/x", cached, bad); err == nil {
		t.Fatal("a download with the wrong digest was accepted")
	}
	if _, err := os.Stat(cached); err == nil {
		t.Fatal("a refused download was cached")
	}
	if _, err := fetch(srv.URL+"/gone", cached, good); err == nil {
		t.Error("a 404 was accepted")
	}
	if b, err := fetch(srv.URL+"/x", cached, good); err != nil || string(b) != "payload" {
		t.Fatalf("%q %v", b, err)
	}
	before := hits
	if _, err := fetch(srv.URL+"/x", cached, good); err != nil || hits != before {
		t.Errorf("the cached copy was not used (%d requests)", hits-before)
	}
	// A cached copy that fails its digest is downloaded again, not trusted.
	os.WriteFile(cached, []byte("tampered"), 0o755)
	if b, err := fetch(srv.URL+"/x", cached, good); err != nil || string(b) != "payload" {
		t.Errorf("a tampered cache was used: %q %v", b, err)
	}
	if _, err := fetch("http://127.0.0.1:1/x", cached+"2", good); err == nil {
		t.Error("an unreachable server was accepted")
	}
}

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if run([]string{"-nope"}, &out, &errb) != 2 || !strings.Contains(errb.String(), "usage") {
		t.Errorf("usage: %q", errb.String())
	}
	errb.Reset()
	if run([]string{"-cache"}, &out, &errb) != 2 {
		t.Error("-cache without a directory was accepted")
	}
	got := 0
	osExit = func(c int) { got = c }
	defer func() { osExit = os.Exit }()
	old := os.Args
	os.Args = []string{"webbuild", "-nope"}
	defer func() { os.Args = old }()
	main()
	if got != 2 {
		t.Errorf("main exited %d", got)
	}
}

func TestSortedAndRoot(t *testing.T) {
	if got := sorted([]string{"b", "c", "a"}); strings.Join(got, "") != "abc" {
		t.Errorf("sorted: %v", got)
	}
	r, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r, "internal", "app", "web", "input.css")); err != nil {
		t.Errorf("the module root %s has no web/input.css: %v", r, err)
	}
}
