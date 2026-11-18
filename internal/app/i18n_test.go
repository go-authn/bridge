// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var keyUse = regexp.MustCompile(`\{\{\s*(?:t|th|tf|tor)\s+"([a-zA-Z0-9.]+)"`)

// Every key a template names is in the catalogue, in both languages; every
// key in the catalogue is used; and a page renders to its end in each language
// (a missing key stops the template, which would leave a page cut short).
func TestCatalogueIsCompleteAndUsed(t *testing.T) {
	used := map[string]bool{}
	for _, k := range dynamicKeys() {
		used[k] = true
	}
	es, err := templateFS.ReadDir("web/templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		b, _ := templateFS.ReadFile("web/templates/" + e.Name())
		for _, m := range keyUse.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
	}
	for k := range used {
		if _, ok := catalogue[k]; !ok {
			t.Errorf("the key %q is used and not in the catalogue", k)
		}
	}
	for k, v := range catalogue {
		if v[0] == "" || v[1] == "" {
			t.Errorf("the key %q lacks a French or an English text", k)
		}
		if !used[k] {
			t.Errorf("the key %q is in the catalogue and nothing uses it", k)
		}
		if strings.HasPrefix(k, "h.") != strings.Contains(v[0], "<") || strings.HasPrefix(k, "h.") != strings.Contains(v[1], "<") {
			t.Errorf("the key %q: markup only in h. keys", k)
		}
		if strings.Count(v[0], "%") != strings.Count(v[1], "%") {
			t.Errorf("the key %q: the two languages take different arguments", k)
		}
	}
	s := &server{cfg: &config{}}
	for _, lang := range []string{langFR, langEN} {
		for name, data := range samplePages() {
			w := httptest.NewRecorder()
			s.show(&langWriter{ResponseWriter: w, lang: lang, next: "/x"}, templateOf(name), data)
			if body := w.Body.String(); !strings.HasSuffix(strings.TrimSpace(body), "</html>") || !strings.Contains(body, `<html lang="`+lang+`">`) {
				t.Errorf("%s (%s) did not render to its end:\n%s", name, lang, body)
			}
		}
	}
	// A key that is not there is an error, not a blank.
	// (A set that has run cannot be extended, so each case has its own.)
	run := func(lang, src string) error {
		ts, err := templatesFor(lang).New("probe").Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		return ts.Execute(httptest.NewRecorder(), nil)
	}
	if err := run(langFR, `{{t "no.such.key"}}`); err == nil || !strings.Contains(err.Error(), "no.such.key") {
		t.Errorf("a missing key: err = %v", err)
	}
	if err := run(langEN, `{{t "skip"}}`); err != nil {
		t.Errorf("a present key: %v", err)
	}
	if err := run(langEN, `{{th "skip"}}`); err == nil {
		t.Error("text was shown as markup")
	}
	if err := run(langEN, `{{tf "no.key" 1}}`); err == nil {
		t.Error("a missing formatted key rendered")
	}
	if err := run(langEN, `{{tor "no.key"}}{{tor "skip"}}{{icon "check" "x"}}`); err != nil {
		t.Errorf("tor: %v", err)
	}
}

// One language per page: nothing the other language says is on it. (The two
// sentences of the account page that said "par X / by X, pas ici / not here"
// were one value, already in both languages, set into each.)
func TestAPageSpeaksOneLanguage(t *testing.T) {
	s := &server{cfg: &config{}}
	for _, lang := range []string{langFR, langEN} {
		other := 1 - langIndex(lang)
		for name, data := range samplePages() {
			w := httptest.NewRecorder()
			s.show(&langWriter{ResponseWriter: w, lang: lang, next: "/x"}, templateOf(name), data)
			body := html.UnescapeString(w.Body.String())
			for k, v := range catalogue {
				if strings.HasPrefix(k, "h.") || strings.Contains(v[other], "%") || v[0] == v[1] {
					continue
				}
				// The text of the other language, when the own language's text
				// does not contain it (an English word inside a French one).
				if strings.Contains(body, v[other]) && !strings.Contains(v[langIndex(lang)], v[other]) {
					t.Errorf("%s (%s) contains the %s text of %q: %q", name, lang, map[int]string{0: "French", 1: "English"}[other], k, v[other])
				}
			}
			if strings.Contains(body, " / ") && !strings.Contains(name, "choose") {
				// A slash between two texts is the old doubling; the sample
				// data has none of its own on these pages.
				for _, line := range strings.Split(body, "\n") {
					if strings.Contains(line, "> / <") || strings.Contains(line, " / <span lang") {
						t.Errorf("%s (%s) doubles a label: %s", name, lang, line)
					}
				}
			}
		}
	}
	// The sentence, exactly, once, in the page's own language.
	render := func(lang, sample string) string {
		w := httptest.NewRecorder()
		s.show(&langWriter{ResponseWriter: w, lang: lang, next: "/x"}, "account", samplePages()[sample])
		return html.UnescapeString(w.Body.String())
	}
	for _, c := range []struct{ lang, sample, want string }{
		{langFR, "account-signed", "Le courriel et les groupes sont modifiés par l'administrateur du service, pas ici."},
		{langEN, "account-signed", "Email and groups are changed by the service's administrator, not here."},
		{langFR, "account-federated", "Le courriel et les groupes sont modifiés par votre établissement, pas ici."},
		{langEN, "account-federated", "Email and groups are changed by your institution, not here."},
	} {
		body := render(c.lang, c.sample)
		if n := strings.Count(body, c.want); n != 1 {
			t.Errorf("%s/%s: the sentence appears %d times", c.lang, c.sample, n)
		}
		if strings.Contains(body, "Mail and groups") || strings.Contains(body, " / the service") {
			t.Errorf("%s/%s: a doubled sentence", c.lang, c.sample)
		}
	}
}

func TestChooseLang(t *testing.T) {
	for _, c := range []struct{ accept, cookie, want string }{
		{"", "", "fr"},
		{"en", "", "en"},
		{"en-US,en;q=0.9,fr;q=0.8", "", "en"},
		{"fr-CH, fr;q=0.9, en;q=0.8", "", "fr"},
		{"de,en;q=0.5", "", "en"},
		{"de,es", "", "fr"},
		{"en;q=0.3,fr;q=0.7", "", "fr"},
		{"fr;q=0,en;q=0.1", "", "en"},
		{"en;q=bad,fr", "", "fr"},
		{"en;q=2", "", "fr"},
		{"EN-gb", "", "en"},
		{"fr,en", "", "fr"},
		{"en,fr", "", "en"},
		{"en", "fr", "fr"},
		{"fr", "en", "en"},
		{"en", "de", "en"},
		{strings.Repeat("x,", 500) + "en", "", "fr"}, // past the cap: ignored
	} {
		r := httptest.NewRequest("GET", "/", nil)
		if c.accept != "" {
			r.Header.Set("Accept-Language", c.accept)
		}
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: langCookie, Value: c.cookie})
		}
		if got := chooseLang(r); got != c.want {
			t.Errorf("Accept-Language %q cookie %q: %s, want %s", c.accept, c.cookie, got, c.want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for next, want := range map[string]string{
		"/account":                      "/account",
		"/local/login?x=1&y=2":          "/local/login?x=1&y=2",
		"":                              "/",
		"account":                       "/",
		"//evil.example":                "/",
		"/\\evil.example":               "/",
		"https://evil.example/":         "/",
		"/%2f%2fevil":                   "/", // decodes to //evil: refused to be safe
		"/a\r\nSet-Cookie: x=1":         "/",
		"/a\tb":                         "/",
		"/" + strings.Repeat("a", 2100): "/",
		"javascript:alert(1)":           "/",
		"/?next=//evil.example":         "/?next=//evil.example",
	} {
		if got := safeNext(next); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", next, got, want)
		}
	}
}

// The switch, and the language of a page, end to end through the middleware.
func TestLanguageSwitch(t *testing.T) {
	s := &server{cfg: &config{Issuer: "https://login.example.org"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/lang/{code}", s.setLang)
	mux.HandleFunc("/page/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		headers(w)
		s.show(w, name, samplePages()[name])
	})
	h := withLang(mux)
	do := func(method, target string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do("GET", "/page/method?a=b", nil)
	body := w.Body.String()
	if !strings.Contains(body, `<html lang="fr">`) || !strings.Contains(body, `href="/lang/en?next=%2fpage%2fmethod%3fa%3db"`) ||
		!strings.Contains(w.Header().Get("Vary"), "Accept-Language") || !strings.Contains(w.Header().Get("Vary"), "Cookie") {
		t.Errorf("French by default, with a switch to English that comes back here:\n%s\n%v", body, w.Header())
	}
	w = do("GET", "/page/method", map[string]string{"Accept-Language": "en-GB,en;q=0.8"})
	if body := w.Body.String(); !strings.Contains(body, `<html lang="en">`) || !strings.Contains(body, `href="/lang/fr?next=`) || !strings.Contains(body, `aria-current="true" lang="en"`) {
		t.Errorf("Accept-Language en:\n%s", body)
	}
	// The pages that cannot take the switch (the invitation is in the URL's
	// fragment, which a reload would lose) have none, and still follow the language.
	for _, p := range []string{"localenroll", "accountopen"} {
		w = do("GET", "/page/"+p, map[string]string{"Accept-Language": "en"})
		if body := w.Body.String(); strings.Contains(body, "/lang/") || !strings.Contains(body, `<html lang="en">`) {
			t.Errorf("%s: switch or language wrong", p)
		}
	}

	// /lang/en sets the cookie and goes back.
	w = do("GET", "/lang/en?next=/local/login%3Fa%3Db", nil)
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == langCookie {
			c = k
		}
	}
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/local/login?a=b" || c == nil || c.Value != "en" ||
		c.SameSite != http.SameSiteLaxMode || !c.HttpOnly || !c.Secure || c.Path != "/" || c.MaxAge <= 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("/lang/en: %d %q %+v", w.Code, w.Header().Get("Location"), c)
	}
	// The cookie wins over Accept-Language, and the page follows it.
	r := httptest.NewRequest("GET", "/page/method", nil)
	r.Header.Set("Accept-Language", "fr")
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if !strings.Contains(rec.Body.String(), `<html lang="en">`) {
		t.Error("the cookie did not win")
	}
	// An open redirect is not offered; neither is another language or method.
	if w = do("GET", "/lang/fr?next=//evil.example", nil); w.Header().Get("Location") != "/" {
		t.Errorf("redirect to %q", w.Header().Get("Location"))
	}
	if w = do("GET", "/lang/de", nil); w.Code != http.StatusNotFound || len(w.Result().Cookies()) != 0 {
		t.Errorf("/lang/de: %d", w.Code)
	}
	if w = do("POST", "/lang/en", nil); w.Code != http.StatusNotFound || len(w.Result().Cookies()) != 0 {
		t.Errorf("POST /lang/en: %d", w.Code)
	}
	// On an http issuer (loopback, for testing) the cookie is not Secure: it
	// would not be stored.
	s2 := &server{cfg: &config{Issuer: "http://localhost:8080"}}
	rec = httptest.NewRecorder()
	s2.setLang(rec, func() *http.Request {
		r := httptest.NewRequest("GET", "/lang/fr", nil)
		r.SetPathValue("code", "fr")
		return r
	}())
	if cs := rec.Result().Cookies(); len(cs) != 1 || cs[0].Secure {
		t.Errorf("cookie on an http issuer: %+v", cs)
	}
	// Without the middleware (a handler called directly) the language is French.
	if l, n := langOf(httptest.NewRecorder()); l != "fr" || n != "/" {
		t.Errorf("langOf: %q %q", l, n)
	}
	// Unwrap keeps http.ResponseController working through the wrapper.
	if err := http.NewResponseController(&langWriter{ResponseWriter: httptest.NewRecorder()}).Flush(); err != nil {
		t.Errorf("flush through the wrapper: %v", err)
	}
}
