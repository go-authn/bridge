// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/webauthn"
)

func homeGet(h http.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// GET / is the home page, in every language; HEAD works; every other unknown
// path (and any other method on /) is still refused.
func TestHomePage(t *testing.T) {
	f := localFixture(t, `
home {
  title = "Mésocentre de Saclay"
  link "Fileshare" { url = "https://files.mesocentre.example/?a=1&b=2" }
  link "<b>Calcul</b>" { url = "https://calcul.mesocentre.example/" }
}
`)
	h := f.s.handler()
	for _, l := range languages {
		w := homeGet(h, "GET", "/", "Cookie", langCookie+"="+l.Code)
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, `<html lang="`+l.Tag+`"`) {
			t.Errorf("%s: GET /: %d", l.Code, w.Code)
		}
		for _, key := range []string{"home.account", "home.links", "ph.what.h"} {
			want, _ := lookup(l.Code, key)
			if !strings.Contains(html.UnescapeString(body), want) {
				t.Errorf("%s: the home page lacks %q (%s)", l.Code, want, key)
			}
		}
		if !strings.Contains(body, `href="/account"`) || !strings.Contains(body, "Mésocentre de Saclay") {
			t.Errorf("%s: no account button, or no title", l.Code)
		}
		// The federation and the combo are there; the page is the design's.
		if !strings.Contains(body, "RENATER") && !strings.Contains(body, "federation") && !strings.Contains(body, "127.0.0.1") {
			t.Errorf("%s: no federation named", l.Code)
		}
		if !strings.Contains(body, `id="lang-select"`) || !strings.Contains(body, `action="/theme"`) {
			t.Errorf("%s: no language combo or theme switch", l.Code)
		}
	}
	// Links are escaped, in attribute and text.
	body := homeGet(h, "GET", "/").Body.String()
	for _, want := range []string{`href="https://files.mesocentre.example/?a=1&amp;b=2"`, "&lt;b&gt;Calcul&lt;/b&gt;", `rel="noopener noreferrer"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the links lack %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<b>Calcul") {
		t.Error("a link name was not escaped")
	}
	// The same headers as every page: no framing, no store, a policy that is
	// the strict one (no connect-src, nothing inline).
	w := homeGet(h, "GET", "/")
	csp := w.Header().Get("Content-Security-Policy")
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe") || strings.Contains(csp, "connect-src") {
		t.Errorf("headers: %v", w.Header())
	}
	if strings.Contains(body, " style=") || strings.Contains(strings.ReplaceAll(body, `<script src="/ui.js"></script>`, ""), "<script") {
		t.Error("an inline script or style")
	}
	// HEAD answers like GET, with no body.
	// (Through a real server: a recorder keeps the body a server would drop.)
	srv := httptest.NewServer(h)
	defer srv.Close()
	hr, err := http.Head(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	hr.Body.Close()
	if hr.StatusCode != http.StatusOK || hr.Header.Get("Content-Type") != "text/html; charset=utf-8" || hr.Header.Get("Content-Security-Policy") != csp {
		t.Errorf("HEAD /: %d %v", hr.StatusCode, hr.Header)
	}
	// Every other path is as unknown as it was.
	for _, p := range []string{"/nope", "/index.html", "/home", "/x/", "/account/nope"} {
		if w := homeGet(h, "GET", p); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, w.Code)
		}
	}
	if w := homeGet(h, "POST", "/"); w.Code == http.StatusOK {
		t.Errorf("POST /: %d", w.Code)
	}
}

// go-authn is the software, not the organisation: the page names the
// configured title (in every language), or "this site", never the software.
// The brand is set too, so the header and footer do not name it either.
func TestHomePageNeverNamesTheSoftware(t *testing.T) {
	titled := localFixture(t, "home {\n title = \"Mésocentre de Saclay\"\n}\nbranding {\n name = \"Mésocentre\"\n}\n")
	plain := localFixture(t, "")
	for _, l := range languages {
		c := "Cookie"
		v := langCookie + "=" + l.Code
		body := html.UnescapeString(homeGet(titled.s.handler(), "GET", "/", c, v).Body.String())
		if strings.Contains(strings.ToLower(body), "go-authn") {
			t.Errorf("%s: a titled home page names the software:\n%s", l.Code, body)
		}
		sentence, _ := lookup(l.Code, "home.p")
		if want := strings.Replace(sentence, "%s", "Mésocentre de Saclay", 1); !strings.Contains(body, want) {
			t.Errorf("%s: the sentence does not name the title: %q", l.Code, want)
		}
		// With no title: "this site", and the main text still never names the
		// software (the header and footer carry the deployment's brand, which
		// defaults to it).
		pb := html.UnescapeString(homeGet(plain.s.handler(), "GET", "/", c, v).Body.String())
		main := pb[strings.Index(pb, "<main"):strings.Index(pb, "</main>")]
		if strings.Contains(strings.ToLower(main), "go-authn") {
			t.Errorf("%s: the untitled main text names the software", l.Code)
		}
		if site, _ := lookup(l.Code, "home.p.site"); !strings.Contains(main, site) {
			t.Errorf("%s: no \"this site\" sentence: %q", l.Code, site)
		}
	}
}

// Nothing about clients, users or keys is shown to an anonymous visitor: not a
// client ID, a redirect URI, an audience, a login, a mail or a key.
func TestHomePageShowsNothingAboutClientsUsersOrKeys(t *testing.T) {
	f := localFixture(t, "")
	f.enrolled("alice", webauthn.AlgES256)
	h := f.s.handler()
	for _, l := range languages {
		body := homeGet(h, "GET", "/", "Cookie", langCookie+"="+l.Code).Body.String()
		for _, secret := range []string{`"web"`, `"cli"`, "redirect", f.redirect, "http://127.0.0.1/callback", "alice", "mesocentre.example", "bob", "client_id", "secret"} {
			if strings.Contains(strings.ToLower(body), strings.ToLower(secret)) {
				t.Errorf("%s: the home page contains %q", l.Code, secret)
			}
		}
	}
	// Control: the same words are on the pages that are for a person, so the
	// check above can fail (the account page of a signed-in person has the login).
	s := f.signedIn(f.enrolled("bob", webauthn.AlgES256), "bob")
	if _, page := f.accountPage(s.cookie); !strings.Contains(page, "bob") {
		t.Fatal("control: the account page does not show the login, the check proves nothing")
	}
}

// A home block is checked at load: https only, escaped text only; the control
// is the same block with a good URL.
func TestHomeBlockRefusals(t *testing.T) {
	f := newFixture(t, "")
	base, err := os.ReadFile(f.cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	try := func(block string) error {
		p := filepath.Join(t.TempDir(), "bridge.hcl")
		os.WriteFile(p, append(append([]byte{}, base...), []byte(block)...), 0o644)
		c, err := loadConfig([]string{p})
		if err == nil {
			c.close()
		}
		return err
	}
	link := func(url string) string {
		return fmt.Sprintf("home {\n link \"Apps\" { url = %q }\n}\n", url)
	}
	if err := try(link("https://apps.mesocentre.example/")); err != nil {
		t.Fatalf("control, a good https link: %v", err)
	}
	if err := try("home {\n title = \"Only a title\"\n}\n"); err != nil {
		t.Errorf("a title alone: %v", err)
	}
	for name, url := range map[string]string{
		"javascript":   "javascript:alert(1)",
		"http":         "http://apps.mesocentre.example/",
		"data":         "data:text/html,<script>alert(1)</script>",
		"mailto":       "mailto:a@b.example",
		"a relative":   "/account",
		"no host":      "https:///x",
		"credentials":  "https://u:p@apps.mesocentre.example/",
		"a quote":      `https://apps.example/"onmouseover="x`,
		"a space":      "https://apps.example/a b",
		"upper scheme": "JAVASCRIPT:alert(1)",
		"empty":        "",
	} {
		err := try(link(url))
		if err == nil || !strings.Contains(err.Error(), "home") {
			t.Errorf("%s: %q accepted (%v)", name, url, err)
		}
	}
	for name, block := range map[string]string{
		"a bidi title":  "home {\n title = \"a\\u202eb\"\n}\n",
		"a long title":  "home {\n title = \"" + strings.Repeat("x", maxHomeTitleRunes+1) + "\"\n}\n",
		"an empty name": "home {\n link \"\" { url = \"https://a.example/\" }\n}\n",
		"two homes":     "home {\n title = \"a\"\n}\nhome {\n title = \"b\"\n}\n",
	} {
		if err := try(block); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var many strings.Builder
	many.WriteString("home {\n")
	for i := 0; i <= maxHomeLinks; i++ {
		fmt.Fprintf(&many, " link \"n%d\" { url = \"https://a.example/%d\" }\n", i, i)
	}
	many.WriteString("}\n")
	if err := try(many.String()); err == nil {
		t.Errorf("%d links accepted", maxHomeLinks+1)
	}
}

func TestFederationName(t *testing.T) {
	for in, want := range map[string]string{
		"https://pub.federation.renater.fr/metadata/fer/idps.xml": "RENATER",
		"https://mds.edugain.org/edugain-v2.xml":                  "eduGAIN",
		"https://metadata.example.org/idps.xml":                   "metadata.example.org",
		"::":                                                      "",
		"":                                                        "",
	} {
		if got := federationName(in); got != want {
			t.Errorf("federationName(%q) = %q, want %q", in, got, want)
		}
	}
}
