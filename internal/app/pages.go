// SPDX-License-Identifier: BSD-3-Clause

package app

import (
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
// anywhere, no base URI, nothing loaded: the policy is the strictest there is
// that still lets a form post.
func pageHeaders(w http.ResponseWriter, formAction string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action "+formAction+"; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

var tmpl = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.}}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#1b1b1b;background:#fff}
@media (prefers-color-scheme:dark){body{color:#eee;background:#161616}a{color:#8cf}}
ul{list-style:none;padding:0}li{margin:.3rem 0}input{font:inherit;padding:.4rem;width:100%;box-sizing:border-box}
button{font:inherit;padding:.4rem 1rem}</style></head><body>{{end}}
{{define "message"}}{{template "head" "Connexion"}}<h1>Connexion</h1><p>{{.}}</p></body></html>{{end}}
{{define "choose"}}{{template "head" "Choisir un établissement"}}
<h1>Choisissez votre établissement</h1><p lang="en">Choose your institution.</p>
<form method="get" action="choose"><input name="q" value="{{.Q}}" placeholder="Nom ou domaine / name or domain" autofocus></form>
<ul>{{range .IdPs}}<li><a href="disco?entityID={{.EntityID}}">{{.Name "fr" "en"}}</a></li>{{else}}<li>Aucun établissement ne correspond.</li>{{end}}</ul>
{{if .More}}<p>{{.More}} autres : précisez la recherche.</p>{{end}}</body></html>{{end}}
{{define "method"}}{{template "head" "Se connecter"}}
<h1>Se connecter</h1><p lang="en">Sign in.</p>
<ul><li><a href="{{.Federation}}">Avec mon établissement (fédération) / With my institution (federation)</a></li>
<li><a href="local/login">Avec un compte local / With a local account</a></li></ul></body></html>{{end}}
{{define "locallogin"}}{{template "head" "Compte local"}}
<h1>Compte local</h1><p lang="en">Local account.</p>
{{if .Error}}<p role="alert"><strong>{{.Error}}</strong></p>{{end}}
<form id="passkey-login" method="post" action="login/finish" data-csrf="{{.CSRF}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="handle"><input type="hidden" name="id"><input type="hidden" name="clientDataJSON">
<input type="hidden" name="authenticatorData"><input type="hidden" name="signature"><input type="hidden" name="userHandle">
<p><button id="passkey-button" type="button" disabled>Se connecter avec une clé d'accès / Sign in with a passkey</button></p>
<p id="passkey-status" role="status"></p></form>
<p><a href="account">Gérer mes clés d'accès / Manage my passkeys</a></p>
<noscript><p>Une clé d'accès demande JavaScript. / A passkey needs JavaScript.</p></noscript>
<script src="passkey.js"></script></body></html>{{end}}
{{define "localaccount"}}{{template "head" "Mes clés d'accès"}}
{{if .Signed}}<h1>Mes clés d'accès</h1><p lang="en">My passkeys.</p>
<div id="account" data-csrf="{{.CSRF}}">
<p>Compte / Account : <strong>{{.Login}}</strong></p>
<ul>{{range .Keys}}<li><code>{{.Prefix}}</code> · créée / created {{.Created}} · {{if .LastUsed}}dernière utilisation / last used {{.LastUsed}}{{else}}jamais utilisée / never used{{end}}{{if .Backup}} · synchronisable / backup-eligible{{end}}{{if .Current}} · <strong>clé de cette confirmation / this confirmation's key</strong>{{end}}
<button type="button" data-remove="{{.Key}}">Supprimer / Remove</button></li>{{end}}</ul>
{{if .Full}}<p>Un compte a au plus {{.Max}} clés : supprimez-en une pour en ajouter. / At most {{.Max}} passkeys: remove one to add another.</p>
{{else}}<p><button id="passkey-button" type="button" data-mode="add" disabled>Ajouter une clé d'accès / Add a passkey</button></p>{{end}}
<p><button id="signout" type="button">Terminer / Done</button></p>
<p id="passkey-status" role="status"></p></div>
{{else}}<h1>Gérer mes clés d'accès</h1><p lang="en">Manage my passkeys.</p>
<p>Confirmez que c'est vous avec une clé d'accès : la confirmation dure cinq minutes. / Confirm it is you with a passkey: the confirmation lasts five minutes.</p>
<p><button id="passkey-button" type="button" data-mode="stepup" disabled>Confirmer avec ma clé d'accès / Confirm with my passkey</button></p>
<p id="passkey-status" role="status"></p>{{end}}
<noscript><p>Une clé d'accès demande JavaScript. / A passkey needs JavaScript.</p></noscript>
<script src="passkey.js"></script></body></html>{{end}}
{{define "localenroll"}}{{template "head" "Enregistrer une clé d'accès"}}
<h1>Enregistrer une clé d'accès</h1><p lang="en">Register a passkey.</p>
<p>Vous avez reçu une invitation d'un administrateur. Votre appareil va vous demander de créer une clé d'accès et de la déverrouiller (empreinte, visage ou code).</p>
<p lang="en">An administrator invited you. Your device will ask you to create a passkey and unlock it (fingerprint, face or PIN).</p>
<p><button id="passkey-button" type="button" data-mode="enroll" disabled>Créer ma clé d'accès / Create my passkey</button></p>
<p id="passkey-status" role="status"></p>
<noscript><p>Une clé d'accès demande JavaScript. / A passkey needs JavaScript.</p></noscript>
<script src="passkey.js"></script></body></html>{{end}}
{{define "device"}}{{template "head" "Connecter un appareil"}}
<h1>Connecter un appareil</h1><p lang="en">Connect a device.</p>
{{if .Error}}<p><strong>{{.Error}}</strong></p>{{end}}
<form method="post" action="device"><label>Code affiché sur l'appareil / code shown on the device<input name="user_code" value="{{.Code}}" autocomplete="off" autocapitalize="characters" autofocus></label>
<p><button>Continuer / Continue</button></p></form></body></html>{{end}}
{{define "confirm"}}{{template "head" "Confirmer"}}
<h1>{{.Client}} demande à se connecter en votre nom</h1>
<p lang="en">{{.Client}} is asking to sign in as you.</p>
<p>Code : <strong>{{.Code}}</strong></p>
<p><strong>Ne continuez que si c'est vous qui avez lancé cette connexion, sur votre propre appareil.</strong> Si quelqu'un vous a transmis ce code, refusez : il obtiendrait l'accès à votre place.</p>
<p lang="en"><strong>Only continue if you started this on your own device.</strong> If somebody sent you this code, refuse: they would get the access, not you.</p>
<form method="post" action="device"><input type="hidden" name="user_code" value="{{.Code}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<button name="confirm" value="yes">Oui, c'est moi / Yes, it is me</button> <button name="confirm" value="no">Non / No</button></form></body></html>{{end}}
`))

// render shows one of the pages above.
func (s *server) render(w http.ResponseWriter, status int, name string, data any) {
	headers(w)
	w.WriteHeader(status)
	tmpl.ExecuteTemplate(w, name, data)
}

// page shows a message. Messages are for people; the detail is in the log.
func (s *server) page(w http.ResponseWriter, status int, msg string) {
	headers(w)
	w.WriteHeader(status)
	tmpl.ExecuteTemplate(w, "message", msg)
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
	tmpl.ExecuteTemplate(w, "choose", map[string]any{"IdPs": list, "Q": r.URL.Query().Get("q"), "More": more})
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
