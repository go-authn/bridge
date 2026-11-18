// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-authn/saml"
)

var errRevoked = errors.New("the token was revoked or has expired")

func urlUnescape(s string) (string, error) { return url.QueryUnescape(s) }

// discovery is /.well-known/openid-configuration (OpenID Connect Discovery
// 1.0, section 3), saying exactly what is offered and nothing more.
func (s *server) discovery(w http.ResponseWriter, r *http.Request) {
	i := s.cfg.Issuer
	grants := []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"}
	if s.cfg.SSF != nil {
		grants = append(grants, "client_credentials") // SSF receivers only
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                i,
		"authorization_endpoint":                i + "/authorize",
		"token_endpoint":                        i + "/token",
		"userinfo_endpoint":                     i + "/userinfo",
		"jwks_uri":                              i + "/jwks",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 grants,
		"device_authorization_endpoint":         i + "/device_authorization",
		"subject_types_supported":               []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "eduperson", "groups"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr",
			"name", "given_name", "family_name", "preferred_username", "email", "groups",
			"eduperson_principal_name", "eduperson_scoped_affiliation", "eduperson_entitlement",
			"entitlements", "eduperson_assurance", "eduperson_orcid", "schac_home_organization", "voperson_id"},
		"authorization_response_iss_parameter_supported": true,
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"claims_parameter_supported":                     false,
	})
}

func (s *server) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Write(jwks(s.cfg.publishedKeys()...))
}

// samlMetadata is this SP's metadata, for the federation's registry.
func (s *server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	b, err := s.spMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}

func (s *server) spMetadata() ([]byte, error) {
	c := s.cfg.SAML
	d := saml.Description{
		Names:            c.Names,
		Descriptions:     c.Descriptions,
		InformationURL:   c.InformationURL,
		PrivacyStatement: c.PrivacyStatement,
		Technical:        c.Technical,
		Attributes: []string{saml.SubjectID, saml.EduPersonPrincipalName, saml.Mail,
			saml.DisplayName, saml.GivenName, saml.Surname},
	}
	if c.Discovery != "" {
		d.Discovery = s.cfg.Issuer + "/saml/disco"
	}
	for _, g := range s.cfg.Claims.Groups {
		d.Attributes = append(d.Attributes, groupAttributes[g])
	}
	return s.sp.Metadata(d)
}

// headers make a page unframeable and keep its URL out of Referer headers.
func headers(w http.ResponseWriter) { pageHeaders(w, "'self'") }

// pageHeaders is headers with the form-action sources a page needs. No script
// anywhere, no base URI, and nothing loaded but this origin's own stylesheet
// and images (style-src and img-src 'self'): no inline style, no 'unsafe-inline',
// no font, no frame. The strictest policy that still draws the page and lets
// a form post.
func pageHeaders(w http.ResponseWriter, formAction string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action "+formAction+"; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Add("Vary", "Accept-Language, Cookie")
}

// The pages are html/template files, one stylesheet (web/static/app.css,
// compiled by internal/webbuild) and Lucide icons (web/icons, ISC licence)
// inlined as SVG by the icon function: nothing is fetched from elsewhere.
//
//go:embed web/templates/*.html
var templateFS embed.FS

//go:embed web/icons/*.svg
var iconFS embed.FS

// icons maps a Lucide icon's name to the markup inside its <svg>, which is
// what the file holds between the tags: a fixed set of paths, from the
// embedded file, never from a request.
var icons = func() map[string]string {
	m := map[string]string{}
	es, err := iconFS.ReadDir("web/icons")
	if err != nil {
		panic(err)
	}
	for _, e := range es {
		b, err := iconFS.ReadFile("web/icons/" + e.Name())
		if err != nil {
			panic(err)
		}
		s := string(b)
		o := strings.Index(s, "<svg")
		i, j := strings.Index(s[max(o, 0):], ">")+max(o, 0), strings.LastIndex(s, "</svg>")
		if o < 0 || i < o || j < i {
			panic("web/icons/" + e.Name() + " is not an <svg> file")
		}
		m[strings.TrimSuffix(e.Name(), ".svg")] = strings.TrimSpace(s[i+1 : j])
	}
	return m
}()

// icon is a Lucide icon at a size the class names. The class comes from a
// template's literal text, the paths from the embedded file.
func icon(name, class string) (template.HTML, error) {
	inner, ok := icons[name]
	if !ok {
		return "", errors.New("no icon " + name)
	}
	return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="` +
		template.HTMLEscapeString(class) + `" aria-hidden="true" focusable="false">` + inner + `</svg>`), nil
}

// pageTitles are the <title>s, and which pages are the wide ones.
var pageTitles = map[string]string{
	"message":     "msg.title",
	"choose":      "choose.ttl",
	"method":      "method.title",
	"locallogin":  "login.title",
	"account":     "acct.title",
	"accountopen": "acct.title",
	"localenroll": "enroll.title",
	"device":      "device.title",
	"confirm":     "confirm.ttl",
}

// show executes a page, in the request's language, with what every page has:
// the deployment's brand, a title and the language switch. data may be nil.
func (s *server) show(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	lang, next := langOf(w)
	data["B"] = s.cfg.brandView()
	data["Lang"] = lang
	data["Title"] = catalogue[pageTitles[name]][langIndex(lang)]
	data["Next"] = next // escaped by the template, in its query context
	// The enrolment page keeps its invitation in the URL's fragment, which a
	// reload through the switch would lose; the auto-submitting page has
	// nothing to switch. Both still follow the cookie and Accept-Language.
	data["Switch"] = name != "localenroll" && name != "accountopen"
	if name == "account" && data["Signed"] == true {
		data["Wide"] = true
	}
	tmplByLang[lang].ExecuteTemplate(w, name, data)
}

// render shows one of the pages above.
func (s *server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	headers(w)
	w.WriteHeader(status)
	s.show(w, name, data)
}

// page shows a message. Messages are for people; the detail is in the log.
func (s *server) page(w http.ResponseWriter, status int, msg string) {
	headers(w)
	w.WriteHeader(status)
	s.show(w, "message", map[string]any{"Msg": msg})
}

// choose is this provider's own list of institutions, for a deployment that
// does not send people to a discovery service.
func (s *server) choose(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.current(r); err != nil {
		s.page(w, http.StatusBadRequest, err.Error())
		return
	}
	md := s.fed.Metadata()
	if md == nil {
		s.page(w, http.StatusServiceUnavailable, "The federation's list of institutions is not available right now.")
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var list []*saml.IdP
	for _, i := range md.Sorted("fr", "en") {
		if !s.allowedIdP(i.EntityID) || !matches(i, q) {
			continue
		}
		list = append(list, i)
	}
	const shown = 50
	more := 0
	if len(list) > shown {
		more = len(list) - shown
		list = list[:shown]
	}
	headers(w)
	s.show(w, "choose", map[string]any{"IdPs": list, "Q": r.URL.Query().Get("q"), "More": more})
}

func matches(i *saml.IdP, q string) bool {
	if q == "" {
		return true
	}
	for _, n := range i.Names {
		if strings.Contains(strings.ToLower(n), q) {
			return true
		}
	}
	for _, d := range i.Domains {
		if strings.Contains(strings.ToLower(d), q) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(i.EntityID), q)
}
