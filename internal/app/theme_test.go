// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func themeServer() (*server, http.Handler) {
	s := &server{cfg: &config{Issuer: "https://login.example.org"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/theme", s.setTheme)
	mux.HandleFunc("GET /ui.js", s.uiScript)
	mux.HandleFunc("/page/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		headers(w)
		s.show(w, name, samplePages()[name])
	})
	return s, withLang(mux)
}

func getReq(h http.Handler,target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var htmlOpen = regexp.MustCompile(`<html[^>]*>`)

// The server draws the theme on <html>, in the first bytes of the page, so
// nothing flashes: no class for system, "dark" or "light" when chosen.
func TestThemeIsDrawnByTheServer(t *testing.T) {
	_, h := themeServer()
	for _, c := range []struct{ cookie, want string }{
		{"", `<html lang="fr">`},
		{"system", `<html lang="fr">`},
		{"dark", `<html lang="fr" class="dark">`},
		{"light", `<html lang="fr" class="light">`},
		{"purple", `<html lang="fr">`}, // not a theme: ignored
		{"dark ", `<html lang="fr">`},
	} {
		var ck []*http.Cookie
		if c.cookie != "" {
			ck = append(ck, &http.Cookie{Name: themeCookie, Value: c.cookie})
		}
		body := getReq(h,"/page/method", ck...).Body.String()
		if got := htmlOpen.FindString(body); got != c.want {
			t.Errorf("theme cookie %q: %s, want %s", c.cookie, got, c.want)
		}
		// <html> is the page's first element: before any style or script.
		if !strings.HasPrefix(body, "<!doctype html>\n<html") {
			t.Errorf("theme cookie %q: the page does not start with <html>", c.cookie)
		}
	}
	// The three buttons say which one is pressed, and name themselves in each
	// language (the words hextra's docs use).
	body := getReq(h,"/page/method", &http.Cookie{Name: themeCookie, Value: "dark"}).Body.String()
	for _, want := range []string{
		`name="theme" value="light" title="Clair" aria-label="Clair" aria-pressed="false"`,
		`name="theme" value="dark" title="Sombre" aria-label="Sombre" aria-pressed="true"`,
		`name="theme" value="system" title="Système" aria-label="Système" aria-pressed="false"`,
		`<form method="get" action="/theme"`, `<meta name="color-scheme" content="dark">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the theme switch lacks %q", want)
		}
	}
	if !strings.Contains(getReq(h,"/page/method").Body.String(), `<meta name="color-scheme" content="light dark">`) {
		t.Error("system: the colour scheme is not both")
	}
	// The words, in the other languages.
	for lang, want := range map[string]string{"de": "Dunkel", "es": "Oscuro", "ja": "ダーク", "ko": "어두운 테마", "zh-cn": "深色", "en": "Dark"} {
		body := getReq(h,"/page/method", &http.Cookie{Name: langCookie, Value: lang}).Body.String()
		if !strings.Contains(body, `title="`+want+`"`) {
			t.Errorf("%s: the dark button is not %q", lang, want)
		}
	}
}

func TestSetTheme(t *testing.T) {
	_, h := themeServer()
	for _, v := range themes {
		w := getReq(h,"/theme?theme="+v+"&next=%2Faccount%3Fx%3D1")
		var c *http.Cookie
		for _, k := range w.Result().Cookies() {
			if k.Name == themeCookie {
				c = k
			}
		}
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account?x=1" || c == nil || c.Value != v ||
			c.SameSite != http.SameSiteLaxMode || c.Path != "/" || !c.HttpOnly || !c.Secure || c.MaxAge <= 0 || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("/theme?theme=%s: %d %q %+v", v, w.Code, w.Header().Get("Location"), c)
		}
	}
	// Refused: another theme, none, another method, an open redirect.
	for _, target := range []string{"/theme?theme=purple", "/theme", "/theme?theme=", "/theme?theme=DARK"} {
		if w := getReq(h,target); w.Code != http.StatusNotFound || len(w.Result().Cookies()) != 0 {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/theme?theme=dark", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("POST /theme: %d", w.Code)
	}
	if w := getReq(h,"/theme?theme=dark&next=//evil.example"); w.Header().Get("Location") != "/" {
		t.Errorf("redirect to %q", w.Header().Get("Location"))
	}
	// The cookie carries the choice and nothing else.
	w = getReq(h,"/theme?theme=dark")
	if sc := w.Header().Get("Set-Cookie"); strings.Count(sc, ";") > 5 || strings.Contains(sc, "csrf") {
		t.Errorf("Set-Cookie: %s", sc)
	}
}

// The header's script is static, from this origin, and only submits the combo
// and hides its button; the CSP lets it run and nothing inline.
func TestHeaderScriptAndPolicy(t *testing.T) {
	_, h := themeServer()
	w := getReq(h,"/ui.js")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(w.Body.String(), `sel.form.submit()`) || strings.Contains(w.Body.String(), "fetch") {
		t.Errorf("/ui.js: %d %v", w.Code, w.Header())
	}
	w = getReq(h,"/page/method")
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "connect-src") {
		t.Errorf("CSP %q is looser than it was", csp)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<script src="/ui.js"></script>`) || regexp.MustCompile(`<script[^>]*>[^<]`).MatchString(body) || strings.Contains(body, " style=") || strings.Contains(body, " onchange") {
		t.Errorf("an inline script or style:\n%s", body)
	}
	// The pages that cannot take a switch (the invitation is in the URL's
	// fragment) have neither the controls nor the script, whatever the theme.
	for _, p := range []string{"localenroll", "accountopen"} {
		body := getReq(h,"/page/"+p, &http.Cookie{Name: themeCookie, Value: "dark"}).Body.String()
		if strings.Contains(body, "/ui.js") || strings.Contains(body, `action="/lang"`) || strings.Contains(body, `action="/theme"`) {
			t.Errorf("%s has the switches", p)
		}
		if !strings.Contains(body, `class="dark"`) {
			t.Errorf("%s does not follow the theme cookie", p)
		}
	}
}

// brand.css: the accent has its computed variants in both themes, and the
// dark ones apply for the class and for the media query unless forced light.
func TestBrandCSSFollowsTheTheme(t *testing.T) {
	accent, _ := parseHex(defaultAccent)
	css := brandCSS(accent)
	for _, want := range []string{":root{", "@media (prefers-color-scheme:dark){\n:root:not(.light){", "\n:root.dark{"} {
		if !strings.Contains(css, want) {
			t.Errorf("brand.css lacks %q:\n%s", want, css)
		}
	}
	// Both dark rules are the same, and legible on the raised dark surface.
	darkRules := regexp.MustCompile(`(?m)^:root(?::not\(\.light\)|\.dark)\{(.*)\}$`).FindAllStringSubmatch(css, -1)
	if len(darkRules) != 2 || darkRules[0][1] != darkRules[1][1] {
		t.Fatalf("dark rules: %v", darkRules)
	}
	ink := regexp.MustCompile(`--brand-ink:(#[0-9a-f]{6})`).FindStringSubmatch(darkRules[0][1])
	lightInk := regexp.MustCompile(`(?m)^:root\{.*--brand-ink:(#[0-9a-f]{6})`).FindStringSubmatch(css)
	if ink == nil || lightInk == nil {
		t.Fatalf("no ink in %s", css)
	}
	parse := func(h string) rgb {
		c, err := parseHex(h)
		if err != nil {
			t.Fatalf("bad colour %s", h)
		}
		return c
	}
	if c := contrast(parse(ink[1]), darkRaised); c < 4.5 {
		t.Errorf("dark ink %s on the raised surface: %.2f:1", ink[1], c)
	}
	if c := contrast(parse(lightInk[1]), white); c < 4.5 {
		t.Errorf("light ink %s on white: %.2f:1", lightInk[1], c)
	}
}

// The stylesheet carries the class-and-media dark variant and CJK system fonts.
func TestStylesheetDarkVariantAndFonts(t *testing.T) {
	b, err := (&brandingBlock{}).build()
	if err != nil {
		t.Fatal(err)
	}
	css := string(b.assets[strings.TrimPrefix(b.CSSURL, "/assets/")].body)
	for _, want := range []string{".dark", ".light", "prefers-color-scheme:dark", "PingFang SC", "Hiragino", "Noto Sans CJK", "Microsoft YaHei", "Malgun Gothic"} {
		if !strings.Contains(css, want) {
			t.Errorf("the stylesheet lacks %q", want)
		}
	}
}
