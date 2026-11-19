// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"bytes"
	"image"
	"image/png"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBrandingValues(t *testing.T) {
	long := strings.Repeat("é", maxBrandNameRunes+1)
	for _, c := range []struct {
		name string
		in   brandingBlock
		bad  string // a substring of the error, "" when accepted
	}{
		{"nothing", brandingBlock{}, ""},
		{"all good", brandingBlock{Name: "Mésocentre", AccentColor: "#0B6E4F", SupportURL: "https://help.example.org/aide"}, ""},
		{"mailto", brandingBlock{SupportURL: "mailto:support@example.org"}, ""},
		{"name at the cap", brandingBlock{Name: strings.Repeat("é", maxBrandNameRunes)}, ""},
		{"name over the cap", brandingBlock{Name: long}, "branding.name"},
		{"name blank", brandingBlock{Name: "   "}, "branding.name"},
		{"name with a newline", brandingBlock{Name: "a\nb"}, "branding.name"},
		{"name with a bidi override", brandingBlock{Name: "ab‮cd"}, "branding.name"},
		{"name with invalid UTF-8", brandingBlock{Name: "a\xffb"}, "branding.name"},
		{"colour without #", brandingBlock{AccentColor: "0b6e4f"}, "branding.accent_color"},
		{"short colour", brandingBlock{AccentColor: "#0b6"}, "branding.accent_color"},
		{"colour not hex", brandingBlock{AccentColor: "#0b6e4g"}, "branding.accent_color"},
		{"colour that closes the rule", brandingBlock{AccentColor: "#000;}</style><script>"}, "branding.accent_color"},
		{"colour as a function", brandingBlock{AccentColor: "red"}, "branding.accent_color"},
		{"http support", brandingBlock{SupportURL: "http://help.example.org"}, "branding.support_url"},
		{"javascript support", brandingBlock{SupportURL: "javascript:alert(1)"}, "branding.support_url"},
		{"data support", brandingBlock{SupportURL: "data:text/html,x"}, "branding.support_url"},
		{"support with credentials", brandingBlock{SupportURL: "https://u:p@help.example.org"}, "branding.support_url"},
		{"support without host", brandingBlock{SupportURL: "https:///x"}, "branding.support_url"},
		{"support with a quote", brandingBlock{SupportURL: `https://help.example.org/"x`}, "branding.support_url"},
		{"support with a space", brandingBlock{SupportURL: "https://help.example.org/a b"}, "branding.support_url"},
		{"support too long", brandingBlock{SupportURL: "https://e.org/" + strings.Repeat("a", maxSupportURLBytes)}, "branding.support_url"},
		{"mailto without address", brandingBlock{SupportURL: "mailto:"}, "branding.support_url"},
		{"unparsable support", brandingBlock{SupportURL: "https://[::1"}, "branding.support_url"},
		{"missing logo", brandingBlock{LogoFile: filepath.Join(t.TempDir(), "none.svg")}, "branding.logo_file"},
	} {
		b, err := (&c.in).build()
		if c.bad == "" {
			if err != nil || b == nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.bad) {
			t.Errorf("%s: err = %v, want one naming %s", c.name, err, c.bad)
		}
	}
}

func pngBytes(w, h int) []byte {
	var b bytes.Buffer
	png.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, h)))
	return b.Bytes()
}

func TestBrandingLogo(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient></defs><g fill="url(#g)"><path d="M0 0h8v8z"/><use href="#p"/></g></svg>`
	huge := append([]byte(`<svg xmlns="http://www.w3.org/2000/svg">`), bytes.Repeat([]byte(" "), maxLogoBytes)...)
	for _, c := range []struct {
		name string
		body []byte
		bad  string
		typ  string
	}{
		{"svg", []byte(good), "", "image/svg+xml"},
		{"png", pngBytes(64, 64), "", "image/png"},
		{"png too wide", pngBytes(maxLogoPixels+1, 1), "pixels", ""},
		{"png truncated", pngBytes(8, 8)[:20], "valid PNG", ""},
		{"too big", append(huge, []byte("</svg>")...), "larger than", ""},
		{"script", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "script", ""},
		{"onload", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`), "event attribute", ""},
		{"foreignObject", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><foreignObject/></svg>`), "not allowed", ""},
		{"style element", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><style>@import 'x'</style></svg>`), "not allowed", ""},
		{"image", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><image href="https://e.org/x.png"/></svg>`), "not allowed", ""},
		{"external use", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><use href="https://e.org/x.svg#a"/></svg>`), "href", ""},
		{"external url()", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://e.org/x)"/></svg>`), "url()", ""},
		{"javascript attribute", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><a/></svg>`), "not allowed", ""},
		{"style attribute with @import", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect style="@import x"/></svg>`), "not allowed", ""},
		{"doctype", []byte(`<!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg"/>`), "DOCTYPE", ""},
		{"processing instruction", []byte(`<?xml-stylesheet href="x.css"?><svg xmlns="http://www.w3.org/2000/svg"/>`), "processing instruction", ""},
		{"not svg", []byte(`<html/>`), "root", ""},
		{"malformed", []byte(`<svg><g></svg>`), "well-formed", ""},
		{"empty", nil, "no <svg>", ""},
		{"text", []byte("hello"), "no <svg>", ""},
	} {
		b, err := (&brandingBlock{LogoFile: write("logo", c.body)}).build()
		if c.bad == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				continue
			}
			a := b.assets[strings.TrimPrefix(b.LogoURL, "/assets/")]
			if a.typ != c.typ || !bytes.Equal(a.body, c.body) {
				t.Errorf("%s: served as %q", c.name, a.typ)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.bad) || !strings.Contains(err.Error(), "branding.logo_file") {
			t.Errorf("%s: err = %v, want one containing %q", c.name, err, c.bad)
		}
	}
	// A directory is not a logo.
	if _, err := (&brandingBlock{LogoFile: dir}).build(); err == nil {
		t.Error("a directory was accepted as a logo")
	}
}

// The default logo is the org's mark, and it passes its own rules.
func TestDefaultLogoIsValid(t *testing.T) {
	if err := checkSVG(defaultLogo); err != nil {
		t.Fatal(err)
	}
}

var onlyHexVars = regexp.MustCompile(`^(?::root(?::not\(\.light\)|\.dark)?\{(?:--brand(?:-on|-hover|-ink)?:#[0-9a-f]{6};?){4}\}\n|@media \(prefers-color-scheme:dark\)\{\n|\}\n)+$`)

func TestBrandCSSIsAccessibleAndOnlyHex(t *testing.T) {
	step := []float64{0, 51, 102, 153, 204, 255}
	for _, r := range step {
		for _, g := range step {
			for _, b := range step {
				a := rgb{r, g, b}
				css := brandCSS(a)
				if !onlyHexVars.MatchString(css) {
					t.Fatalf("%s: brand.css is not four hex custom properties twice:\n%s", a.hex(), css)
				}
				fill, on := a, white
				if contrast(fill, black) > contrast(fill, white) {
					on = black
				}
				if c := contrast(fill, on); c < 4.5 {
					t.Errorf("%s: the button text has contrast %.2f", a.hex(), c)
				}
				if c := contrast(legibleOn(a, white, black, 4.8), white); c < 4.5 {
					t.Errorf("%s: the accent as text on light has contrast %.2f", a.hex(), c)
				}
				if c := contrast(legibleOn(a, darkRaised, white, 4.8), darkRaised); c < 4.5 {
					t.Errorf("%s: the accent as text on dark has contrast %.2f", a.hex(), c)
				}
			}
		}
	}
	// The default accent is already legible: its ink is itself.
	d, _ := parseHex(defaultAccent)
	if legibleOn(d, white, black, 4.8) != d {
		t.Error("the default accent had to be darkened to read on white")
	}
}

func TestAssetRoute(t *testing.T) {
	b, err := (&brandingBlock{AccentColor: "#0b6e4f"}).build()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: &config{brand: b}}
	get := func(method, name string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/assets/"+name, nil)
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		s.asset(w, r)
		return w
	}
	for _, u := range []struct{ url, typ string }{{b.CSSURL, "text/css"}, {b.BrandCSSURL, "text/css"}, {b.LogoURL, "image/svg+xml"}} {
		name := strings.TrimPrefix(u.url, "/assets/")
		w := get("GET", name)
		h := w.Header()
		if w.Code != 200 || !strings.HasPrefix(h.Get("Content-Type"), u.typ) || h.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.Contains(h.Get("Cache-Control"), "immutable") || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || w.Body.Len() == 0 {
			t.Errorf("%s: %d %v", name, w.Code, h)
		}
		if w := get("HEAD", name); w.Code != 200 || w.Body.Len() != 0 {
			t.Errorf("HEAD %s: %d with %d bytes", name, w.Code, w.Body.Len())
		}
		if w := get("POST", name); w.Code != http.StatusNotFound {
			t.Errorf("POST %s: %d", name, w.Code)
		}
	}
	// Only the names the pages link are served: not a neighbour, not a path,
	// not the name with another hash.
	for _, n := range []string{"app.css", "app.000000000000.css", "../app.css", "logo.svg", "brand.css", "", "config.go"} {
		if w := get("GET", n); w.Code != http.StatusNotFound {
			t.Errorf("/assets/%s: %d", n, w.Code)
		}
	}
	if !strings.Contains(get("GET", strings.TrimPrefix(b.BrandCSSURL, "/assets/")).Body.String(), "#0b6e4f") {
		t.Error("brand.css does not carry the accent")
	}
	// The name of an asset is its content: another accent, another URL.
	b2, _ := (&brandingBlock{AccentColor: "#aa0000"}).build()
	if b2.BrandCSSURL == b.BrandCSSURL || b2.CSSURL != b.CSSURL || b2.LogoURL != b.LogoURL {
		t.Errorf("the URLs do not follow the content: %v %v", b.BrandCSSURL, b2.BrandCSSURL)
	}
	// And a config built by hand has the default brand, not a nil one.
	if (&config{}).brandView() != defaultBrand {
		t.Error("no brand for a config without one")
	}
}

// The stylesheet is generated and self-contained.
func TestStylesheetIsSelfContained(t *testing.T) {
	css := string(appCSS)
	for _, bad := range []string{"@import", "url(http", "url(//", "@font-face", "expression("} {
		if strings.Contains(css, bad) {
			t.Errorf("app.css contains %q", bad)
		}
	}
	for _, want := range []string{".btn-primary", ".surface", ".field", "prefers-color-scheme:dark", "--color-brand"} {
		if !strings.Contains(css, want) {
			t.Errorf("app.css lacks %q", want)
		}
	}
}

var iconCall = regexp.MustCompile(`icon "([a-z0-9-]+)"`)

// Every icon a template names is shipped, and every icon shipped is used and
// listed for the generator.
func TestIconsAreExactlyTheOnesUsed(t *testing.T) {
	used := map[string]bool{}
	err := fs.WalkDir(templateFS, "web/templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := templateFS.ReadFile(p)
		for _, m := range iconCall.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := os.ReadFile("web/icons.txt")
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may have converted the line endings.
	listed = bytes.ReplaceAll(listed, []byte("\r\n"), []byte("\n"))
	for n := range used {
		if _, ok := icons[n]; !ok {
			t.Errorf("a template uses the icon %q, which is not shipped", n)
		}
		if !strings.Contains("\n"+string(listed), "\n"+n+"\n") {
			t.Errorf("the icon %q is not in icons.txt", n)
		}
	}
	for n := range icons {
		if !used[n] {
			t.Errorf("the icon %q is shipped and no template uses it", n)
		}
	}
	if _, err := icon("nope", ""); err == nil {
		t.Error("an unknown icon was drawn")
	}
	if got, _ := icon("check", `a"b`); !strings.Contains(string(got), `class="a&#34;b"`) || !strings.Contains(string(got), `aria-hidden="true"`) {
		t.Errorf("icon markup: %s", got)
	}
}

// brandedPages renders every page with the sample data the screenshots use.
func TestPagesCarryTheBrandAndNothingInline(t *testing.T) {
	hostile := `<script>alert(1)</script>"'`
	b, err := (&brandingBlock{Name: hostile, SupportURL: "https://help.example.org/?a=1&b=2"}).build()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: &config{brand: b}}
	for name, data := range samplePages() {
		w := httptest.NewRecorder()
		s.show(w, templateOf(name), data)
		body := w.Body.String()
		if strings.Contains(body, "<style") || strings.Contains(body, " style=") || strings.Contains(body, "<script>") || strings.Contains(body, "javascript:") {
			t.Errorf("%s: inline style or script:\n%s", name, body)
		}
		for _, want := range []string{`<link rel="stylesheet" href="` + b.CSSURL + `">`, `href="` + b.BrandCSSURL + `"`, `src="` + b.LogoURL + `"`, `lang="fr"`, `name="viewport"`, "&lt;script&gt;alert(1)&lt;/script&gt;"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
		// The passkey script, and the header's static one (/ui.js).
		if strings.Count(strings.ReplaceAll(body, `<script src="/ui.js"></script>`, ""), "<script") > 1 {
			t.Errorf("%s runs more than one script besides /ui.js", name)
		}
		if !strings.Contains(body, "<h1") || !strings.Contains(body, `<main id="main"`) || !strings.Contains(body, `href="#main"`) {
			t.Errorf("%s lacks its heading, landmark or skip link", name)
		}
		if strings.Contains(body, "https://help.example.org/?a=1&amp;b=2") == false && name == "locallogin" {
			t.Errorf("%s: the support link is not escaped as an attribute:\n%s", name, body)
		}
		// Every control in a form has a name a screen reader can read: a
		// <label for>, or text inside the button.
		for _, id := range regexp.MustCompile(`<input id="([a-z_]+)"`).FindAllStringSubmatch(body, -1) {
			if !strings.Contains(body, `for="`+id[1]+`"`) {
				t.Errorf("%s: the input %s has no label", name, id[1])
			}
		}
		if strings.Contains(body, `id="passkey-status"`) && !strings.Contains(body, `role="status" aria-live="polite"`) {
			t.Errorf("%s: the passkey status is not a live region", name)
		}
	}
	// The page headers: this origin's stylesheet and images, and no inline style.
	w := httptest.NewRecorder()
	pageHeadersScript(w, "'self'")
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "style-src 'self'", "img-src 'self'", "script-src 'self'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	w = httptest.NewRecorder()
	headers(w)
	csp = w.Header().Get("Content-Security-Policy")
	// Only the header's static same-origin script (ui.js): no connect-src, no inline.
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "connect-src") || !strings.Contains(csp, "script-src 'self';") || !strings.Contains(csp, "style-src 'self'") {
		t.Errorf("CSP of a page without the passkey script: %q", csp)
	}
}

func TestConfigBrandingBlock(t *testing.T) {
	c := newConf(t)
	// Forward slashes: the path is pasted into an HCL string.
	logo := filepath.ToSlash(filepath.Join(c.dir, "logo.png"))
	os.WriteFile(logo, pngBytes(32, 32), 0o644)
	with := func(block string) string { return c.hcl(func(s string) string { return s + block }) }

	cfg, err := c.load(t, with(`
branding {
  name         = "Mésocentre"
  logo_file    = "`+logo+`"
  accent_color = "#0b6e4f"
  support_url  = "https://help.example.org"
}`))
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.brandView()
	if b.Name != "Mésocentre" || b.SupportURL != "https://help.example.org" || !strings.HasSuffix(b.LogoURL, ".png") {
		t.Errorf("brand: %+v", b)
	}
	// Absent: the neutral theme.
	cfg, err = c.load(t, c.hcl(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.brandView().Name != defaultBrandName || !strings.HasSuffix(cfg.brandView().LogoURL, ".svg") {
		t.Errorf("default brand: %+v", cfg.brandView())
	}
	// Refused at load, naming the field.
	for _, bad := range []string{`accent_color = "blue"`, `support_url = "javascript:alert(1)"`, `logo_file = "/nonexistent/logo.svg"`, `name = "a\nb"`} {
		if _, err := c.load(t, with("branding {\n"+bad+"\n}\n")); err == nil || !strings.Contains(err.Error(), "branding.") {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}
