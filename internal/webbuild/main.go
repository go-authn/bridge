// SPDX-License-Identifier: BSD-3-Clause

// Command webbuild regenerates what the pages ship that nobody writes by
// hand: the one stylesheet (Tailwind CSS v4, compiled here, at build time) and
// the icons (Lucide, copied verbatim from a pinned lucide-static release).
//
//	go run ./internal/webbuild          regenerate internal/app/web
//	go run ./internal/webbuild -check   fail when what is committed differs
//
// Nothing is installed: the Tailwind standalone CLI is downloaded for the
// running platform and used only if its sha256 is the one pinned below; the
// Lucide tarball likewise, by the sha512 the npm registry publishes. A
// download whose digest is not the pinned one is refused before it is run or
// unpacked. @tailwindcss/forms is not a separate download: the standalone CLI
// bundles it, so it is pinned by the CLI's own version and digest.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	tailwindVersion = "v4.3.5"
	// The sha256 of each standalone CLI, from the release's sha256sums.txt.
	// The Windows binary is run as tailwindcss-windows-x64.exe.
	lucideVersion = "1.75.0"
	// The sha512 the npm registry publishes for lucide-static-1.75.0.tgz.
	lucideIntegrity = "vtAnJzxoH8jp0++Ydf22CPAAL3WfQQjmDG+OuRlG+CXouLCrlfTz7zWuDvHkTtj61czkhJAISChHDXkxLLqKRw=="
)

var tailwindSums = map[string]string{
	"linux-arm64":    "ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad",
	"linux-x64":      "e47695cee3f0d90623a91f3939b08bdee610eb5ad99340adff9d4145b284d6cc",
	"macos-arm64":    "f3f4f5d1727e2b693b8f1c9a1492b5dd87008c86ea286bee1589cb458e6235fc",
	"macos-x64":      "a63702686a3ed048b3135d84a73be49ea9d47f880c9b20e54b3ef60934ad8cdf",
	"windows-x64":    "2803583268c53f4713e89943e211081fddb186c0a4a7d07b5c342c6ae853ec95",
	"linux-x64-musl": "bb050edd13f15006d872a9bb1772b908618a8df6806d30bf095cba26a09e640b",
}

// maxDownload bounds what is read from the network.
const maxDownload = 256 << 20

var osExit = os.Exit

func main() { osExit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func platform() (string, error) {
	var os_ string
	switch runtime.GOOS {
	case "linux", "windows":
		os_ = runtime.GOOS
	case "darwin":
		os_ = "macos"
	default:
		return "", fmt.Errorf("no Tailwind standalone CLI for %s", runtime.GOOS)
	}
	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "arm64"
	default:
		return "", fmt.Errorf("no Tailwind standalone CLI for %s", runtime.GOARCH)
	}
	return os_ + "-" + arch, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	check := false
	cache := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-check":
			check = true
		case "-cache":
			i++
			if i == len(args) {
				fmt.Fprintln(stderr, "webbuild: -cache needs a directory")
				return 2
			}
			cache = args[i]
		default:
			fmt.Fprintf(stderr, "usage: webbuild [-check] [-cache dir]\n")
			return 2
		}
	}
	if err := build(check, cache, stdout); err != nil {
		fmt.Fprintln(stderr, "webbuild:", err)
		return 1
	}
	return 0
}

func build(check bool, cache string, out io.Writer) error {
	root, err := findRoot()
	if err != nil {
		return err
	}
	web := filepath.Join(root, "internal", "app", "web")
	if cache == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		cache = filepath.Join(d, "authn-bridge-web")
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	names, err := iconNames(filepath.Join(web, "icons.txt"))
	if err != nil {
		return err
	}

	// Icons.
	tgz, err := fetch(fmt.Sprintf("https://registry.npmjs.org/lucide-static/-/lucide-static-%s.tgz", lucideVersion), filepath.Join(cache, "lucide-static-"+lucideVersion+".tgz"), func(b []byte) error {
		return verifySRI(b, lucideIntegrity)
	})
	if err != nil {
		return err
	}
	icons, license, err := extractIcons(tgz, names)
	if err != nil {
		return err
	}
	files := map[string][]byte{"icons/LICENSE": license}
	for n, b := range icons {
		files["icons/"+n+".svg"] = b
	}

	// Stylesheet.
	plat, err := platform()
	if err != nil {
		return err
	}
	want := tailwindSums[plat]
	bin := filepath.Join(cache, "tailwindcss-"+tailwindVersion+"-"+plat)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	asset := "tailwindcss-" + plat
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	if _, err := fetch("https://github.com/tailwindlabs/tailwindcss/releases/download/"+tailwindVersion+"/"+asset, bin, func(b []byte) error {
		return verifySHA256(b, want)
	}); err != nil {
		return err
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(cache, "css-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	cssOut := filepath.Join(tmp, "app.css")
	cmd := exec.Command(bin, "-i", "input.css", "-o", cssOut, "--minify")
	cmd.Dir = web
	var msg bytes.Buffer
	cmd.Stdout, cmd.Stderr = &msg, &msg
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tailwindcss: %v\n%s", err, msg.String())
	}
	css, err := os.ReadFile(cssOut)
	if err != nil {
		return err
	}
	files["static/app.css"] = css

	// Write, or compare.
	var stale []string
	for rel, b := range files {
		p := filepath.Join(web, filepath.FromSlash(rel))
		have, err := os.ReadFile(p)
		same := err == nil && bytes.Equal(have, b)
		if same {
			continue
		}
		if check {
			stale = append(stale, rel)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", rel)
	}
	if len(stale) > 0 {
		return fmt.Errorf("committed files differ from what the pinned tools generate (run `go run ./internal/webbuild` and commit): %s", strings.Join(sorted(stale), ", "))
	}
	fmt.Fprintf(out, "webbuild: tailwindcss %s, lucide-static %s, %d icons, %d bytes of CSS: ok\n", tailwindVersion, lucideVersion, len(names), len(css))
	return nil
}

func sorted(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}

// findRoot is the module root, found from the working directory.
func findRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		p := filepath.Dir(d)
		if p == d {
			return "", errors.New("no go.mod above the working directory")
		}
		d = p
	}
}

// iconNames reads icons.txt: one Lucide icon name per line, # for comments.
func iconNames(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseNames(f)
}

func parseNames(r io.Reader) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, fmt.Errorf("icons.txt: %q is not a Lucide icon name", l)
			}
		}
		if seen[l] {
			return nil, fmt.Errorf("icons.txt: %q is listed twice", l)
		}
		seen[l] = true
		out = append(out, l)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("icons.txt lists no icon")
	}
	return out, nil
}

// fetch returns the bytes at url, from the cache when the cached copy passes
// verify, and verified either way before it is cached or returned.
func fetch(url, cached string, verify func([]byte) error) ([]byte, error) {
	if b, err := os.ReadFile(cached); err == nil && verify(b) == nil {
		return b, nil
	}
	c := &http.Client{Timeout: 5 * time.Minute}
	res, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDownload {
		return nil, fmt.Errorf("%s: more than %d bytes", url, maxDownload)
	}
	if err := verify(b); err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if err := os.WriteFile(cached, b, 0o755); err != nil {
		return nil, err
	}
	return b, nil
}

func verifySHA256(b []byte, want string) error {
	if want == "" {
		return errors.New("no sha256 is pinned for this platform")
	}
	got := sha256.Sum256(b)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("sha256 is %x, not the pinned %s", got, want)
	}
	return nil
}

func verifySRI(b []byte, want string) error {
	got := sha512.Sum512(b)
	if base64.StdEncoding.EncodeToString(got[:]) != want {
		return errors.New("sha512 is not the pinned integrity")
	}
	return nil
}

// extractIcons returns package/icons/<name>.svg for each name, and the
// package's LICENSE, from a gzipped tar. An icon the release does not have is
// an error, not a gap.
func extractIcons(tgz []byte, names []string) (map[string][]byte, []byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, nil, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want["package/icons/"+n+".svg"] = true
	}
	icons := map[string][]byte{}
	var license []byte
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if h.Typeflag != tar.TypeReg || h.Size > 1<<20 {
			continue
		}
		name := path.Clean(h.Name)
		if !want[name] && name != "package/LICENSE" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, nil, err
		}
		if name == "package/LICENSE" {
			license = b
			continue
		}
		icons[strings.TrimSuffix(strings.TrimPrefix(name, "package/icons/"), ".svg")] = b
	}
	for _, n := range names {
		if icons[n] == nil {
			return nil, nil, fmt.Errorf("lucide-static %s has no icon %q", lucideVersion, n)
		}
	}
	if license == nil {
		return nil, nil, errors.New("lucide-static has no LICENSE")
	}
	return icons, license, nil
}
