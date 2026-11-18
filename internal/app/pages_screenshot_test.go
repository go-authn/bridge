// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package app

import (
	"context"
	"encoding/json"
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

// TestPageScreenshots draws every page in the real Chrome, under the pages'
// real headers (so a style the policy refuses would show as an unstyled page
// and fail the assertions below), and writes a PNG of each for review: in
// French, light, dark and system (the browser's scheme decides), and the
// choice, local login and account pages in each of the seven languages. A
// forced theme must beat the browser's scheme, which is asserted from the
// computed background. The pages are the real templates and the real
// stylesheet, served by the real asset route, with the sample data of
// pages_sample_test.go: the login states some of them need are covered by the
// lifecycle test. The languages are also drawn on a 360 px screen, where a
// long CJK label must wrap and not push the page sideways.
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
	mux.HandleFunc("GET /ui.js", s.uiScript)
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
		if l := r.URL.Query().Get("lang"); isLang(l) {
			lang = l
		}
		theme := themeSystem
		if v := r.URL.Query().Get("theme"); isTheme(v) {
			theme = v
		}
		s.show(&langWriter{ResponseWriter: w, lang: lang, next: r.URL.RequestURI(), theme: theme}, tn, data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// scheme is what the browser asks for; theme is the cookie's value.
	type shot struct {
		name, lang, theme, scheme string
		width                     int
		save                      bool
	}
	var shots []shot
	for _, n := range names {
		shots = append(shots,
			shot{n, langFR, themeLight, "light", 900, true},
			shot{n, langFR, themeDark, "dark", 900, true},
			shot{n, langFR, themeSystem, "light", 900, true},
			shot{n, langFR, themeSystem, "dark", 900, true},
			// A chosen theme beats the browser's scheme: asserted, not saved.
			shot{n, langFR, themeLight, "dark", 900, false},
			shot{n, langFR, themeDark, "light", 900, false})
		if tn := templateOf(n); tn == "choose" || tn == "locallogin" || tn == "account" {
			for _, l := range languages {
				if l.Code != langFR {
					shots = append(shots, shot{n, l.Code, themeLight, "light", 900, true}, shot{n, l.Code, themeDark, "dark", 900, true})
				}
				shots = append(shots, shot{n, l.Code, themeLight, "light", 360, l.Code == langJA || l.Code == langKO || l.Code == langZH || l.Code == langDE})
			}
		}
	}
	saved := 0
	for _, sh := range shots {
		name := sh.name
		// What the page must look like: the theme, else the browser's scheme.
		look := sh.theme
		if look == themeSystem {
			look = sh.scheme
		}
		p := &page{t: t, ctx: ctx}
		p.call(func(ctx context.Context, tg *chromedp.Target) error {
			if _, err := cdp.Call(ctx, tg, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
				Features: []*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: sh.scheme}}}); err != nil {
				return err
			}
			_, err := cdp.Call(ctx, tg, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{Width: int64(sh.width), Height: 800, DeviceScaleFactor: 1})
			return err
		})
		p.goTo(srv.URL + "/shot/" + name + "?lang=" + sh.lang + "&theme=" + sh.theme)
		label := fmt.Sprintf("%s (%s, %s theme, %s browser, %dpx)", name, sh.lang, sh.theme, sh.scheme, sh.width)
		var htmlLang string
		p.eval(`document.documentElement.lang`, &htmlLang)
		if htmlLang != langTag(sh.lang) {
			p.fatalf("%s: <html lang> is %q, want %s", label, htmlLang, langTag(sh.lang))
		}
		// The stylesheet was applied under the page's own CSP: a card has
		// rounded corners, the body has the theme's background, and the logo has
		// loaded.
		var radius, bg string
		var logoOK bool
		p.eval(`getComputedStyle(document.querySelector("section, .surface") || document.body).borderTopLeftRadius`, &radius)
		// The computed colour may be written in any colour space (Tailwind
		// writes oklch); a canvas turns it into the sRGB bytes.
		p.eval(`(() => { const c = document.createElement("canvas").getContext("2d"); c.fillStyle = getComputedStyle(document.body).backgroundColor; c.fillRect(0, 0, 1, 1); return Array.from(c.getImageData(0, 0, 1, 1).data.slice(0, 3)).join(","); })()`, &bg)
		p.eval(`(() => { const i = document.querySelector("header img"); return !!i && i.complete && i.naturalWidth > 0; })()`, &logoOK)
		wantBg := map[string]string{"light": "248,250,252", "dark": "18,21,26"}[look]
		if radius == "0px" || bg != wantBg || !logoOK {
			p.fatalf("%s: radius=%q background=%q (want %s) logo loaded=%v", label, radius, bg, wantBg, logoOK)
		}
		var overflow bool
		p.eval(`document.documentElement.scrollWidth > document.documentElement.clientWidth`, &overflow)
		if overflow {
			p.fatalf("%s: the page scrolls sideways", label)
		}
		// The accent is legible in the theme that shows: the link ink on the
		// page background reaches AA (4.5:1).
		var ratioJSON string
		p.eval(`JSON.stringify((() => {
			const rgb = (v) => { const c = document.createElement("canvas").getContext("2d"); c.fillStyle = v; c.fillRect(0, 0, 1, 1); return Array.from(c.getImageData(0, 0, 1, 1).data.slice(0, 3)); };
			const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
			const a = document.querySelector("a[href]:not(.skip)"); if (!a) { return 21; }
			const l1 = lum(rgb(getComputedStyle(a).color)), l2 = lum(rgb(getComputedStyle(document.body).backgroundColor));
			return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
		})())`, &ratioJSON)
		var ratio float64
		if err := json.Unmarshal([]byte(ratioJSON), &ratio); err != nil || ratio < 4.5 {
			p.fatalf("%s: link contrast %.2f:1 is below AA", label, ratio)
		}
		// The combo and the buttons are on the page, and the script hid the
		// submit button (a browser with script).
		var combo struct {
			Options int
			Value   string
			GoShown bool
			Pressed string
		}
		var comboJSON string
		p.eval(`JSON.stringify((() => { const s = document.getElementById("lang-select"); const g = document.getElementById("lang-go"); const pr = document.querySelector('.seg [aria-pressed="true"]');
			return s ? {Options: s.options.length, Value: s.value, GoShown: !!g && g.offsetParent !== null, Pressed: pr ? pr.value : ""} : {Options: 0, Value: "", GoShown: false, Pressed: ""}; })())`, &comboJSON)
		if err := json.Unmarshal([]byte(comboJSON), &combo); err != nil {
			p.fatalf("%s: combo: %v", label, err)
		}
		if tn := templateOf(name); tn != "localenroll" && tn != "accountopen" {
			if combo.Options != len(languages) || combo.Value != sh.lang || combo.GoShown || combo.Pressed != sh.theme {
				p.fatalf("%s: combo %+v", label, combo)
			}
		}
		if !sh.save {
			continue
		}
		png, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		// fr-light-name.png ... : language, theme (system also says the
		// browser's scheme), then the page; 360 px ones say so.
		mode := sh.theme
		if sh.theme == themeSystem {
			mode = "system-" + sh.scheme
		}
		if sh.width != 900 {
			mode += fmt.Sprintf("-%dpx", sh.width)
		}
		file := filepath.Join(dir, fmt.Sprintf("%s-%s-%s.png", sh.lang, mode, strings.ReplaceAll(name, "/", "_")))
		if err := os.WriteFile(file, png, 0o644); err != nil {
			t.Fatal(err)
		}
		saved++
	}
	t.Logf("%d screenshots in %s", saved, dir)
}
