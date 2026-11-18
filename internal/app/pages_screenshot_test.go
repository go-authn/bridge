// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// screenshotDir is where the page screenshots go: BRIDGE_SCREENSHOT_DIR, or a
// directory under the user's config directory. Never a directory inside a
// repository: a capture of a page does not belong in one.
func screenshotDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("BRIDGE_SCREENSHOT_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			t.Skipf("no place for the screenshots: %v", err)
		}
		dir = filepath.Join(base, "authn-bridge", "page-screenshots")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			t.Fatalf("the screenshot directory %s is inside the repository at %s", abs, d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestPageScreenshots draws every page, in light and in dark, in the real
// Chrome, under the pages' real headers (so a style the policy refuses would
// show as an unstyled page and fail the assertions below), and writes a PNG of
// each for review. The pages are the real templates and the real stylesheet,
// served by the real asset route, with the sample data of pages_sample_test.go:
// the login states some of them need are covered by the lifecycle test.
func TestPageScreenshots(t *testing.T) {
	ctx := startChrome(t)
	dir := screenshotDir(t)

	b, err := (&brandingBlock{}).build()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: &config{brand: b}}
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/{name}", s.asset)
	samples := samplePages()
	var names []string
	for n := range samples {
		names = append(names, n)
	}
	sort.Strings(names)
	mux.HandleFunc("/shot/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		data, ok := samples[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		tn := templateOf(name)
		if tn == "account" || tn == "locallogin" || tn == "localenroll" || tn == "accountopen" {
			pageHeadersScript(w, "'self'")
		} else {
			headers(w)
		}
		lang := langFR
		if r.URL.Query().Get("lang") == langEN {
			lang = langEN
		}
		s.show(&langWriter{ResponseWriter: w, lang: lang, next: r.URL.RequestURI()}, tn, data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Every page in French; the English variants of the sign-in choices and of
	// the account space.
	type shot struct{ name, lang string }
	var shots []shot
	for _, n := range names {
		shots = append(shots, shot{n, langFR})
		if tn := templateOf(n); tn == "choose" || tn == "locallogin" || tn == "account" {
			shots = append(shots, shot{n, langEN})
		}
	}
	for _, scheme := range []string{"light", "dark"} {
		for _, sh := range shots {
			name := sh.name
			p := &page{t: t, ctx: ctx}
			p.call(func(ctx context.Context, tg *chromedp.Target) error {
				if _, err := cdp.Call(ctx, tg, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
					Features: []*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: scheme}}}); err != nil {
					return err
				}
				_, err := cdp.Call(ctx, tg, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{Width: 900, Height: 800, DeviceScaleFactor: 1})
				return err
			})
			p.goTo(srv.URL + "/shot/" + name + "?lang=" + sh.lang)
			var htmlLang string
			p.eval(`document.documentElement.lang`, &htmlLang)
			if htmlLang != sh.lang {
				p.fatalf("%s: <html lang> is %q, want %s", name, htmlLang, sh.lang)
			}
			// The stylesheet was applied under the page's own CSP: a card has
			// rounded corners, the body has the scheme's background, and the
			// logo has loaded.
			var radius, bg string
			var logoOK bool
			p.eval(`getComputedStyle(document.querySelector("section, .surface") || document.body).borderTopLeftRadius`, &radius)
			// The computed colour may be written in any colour space (Tailwind
			// writes oklch); a canvas turns it into the sRGB bytes.
			p.eval(`(() => { const c = document.createElement("canvas").getContext("2d"); c.fillStyle = getComputedStyle(document.body).backgroundColor; c.fillRect(0, 0, 1, 1); return Array.from(c.getImageData(0, 0, 1, 1).data.slice(0, 3)).join(","); })()`, &bg)
			p.eval(`(() => { const i = document.querySelector("header img"); return !!i && i.complete && i.naturalWidth > 0; })()`, &logoOK)
			wantBg := map[string]string{"light": "248,250,252", "dark": "18,21,26"}[scheme]
			if radius == "0px" || bg != wantBg || !logoOK {
				p.fatalf("%s (%s): radius=%q background=%q (want %s) logo loaded=%v", name, scheme, radius, bg, wantBg, logoOK)
			}
			var overflow bool
			p.eval(`document.documentElement.scrollWidth > document.documentElement.clientWidth`, &overflow)
			if overflow {
				p.fatalf("%s (%s): the page scrolls sideways", name, scheme)
			}
			png, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
			if err != nil {
				t.Fatalf("%s (%s): %v", name, scheme, err)
			}
			suffix := ""
			if sh.lang == langEN {
				suffix = "-en"
			}
			file := filepath.Join(dir, fmt.Sprintf("%s%s-%s.png", strings.ReplaceAll(name, "/", "_"), suffix, scheme))
			if err := os.WriteFile(file, png, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("%d screenshots in %s", 2*len(shots), dir)
}
