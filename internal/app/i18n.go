// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// A page is shown in ONE language: the one in the lang cookie, else the one
// Accept-Language prefers among the seven below, else French. Every string a
// page shows is in the catalogue, in all seven languages; the templates name a
// key ({{t "key"}}), and a key that is missing is an error the tests catch, not
// a blank. The language combo in the header is a form (GET /lang) that sets the
// cookie and goes back: it works without script.
//
// The languages are those of the fleet's documentation sites (Hugo/hextra:
// content/{fr,en,de,es,ja,ko,zh-cn}); the words for light, dark and system
// are the ones hextra's own i18n files use. The German, Spanish, Japanese,
// Korean and Chinese texts were written without a native review.
const (
	langFR = "fr"
	langEN = "en"
	langDE = "de"
	langES = "es"
	langJA = "ja"
	langKO = "ko"
	langZH = "zh-cn"
	// langCookie is not a session and carries nothing but the choice.
	langCookie = "lang"
)

// language is a language a page can be in: the code of the cookie and of the
// /lang route, the BCP 47 tag of <html lang>, and its name in itself.
type language struct{ Code, Tag, Name string }

var languages = []language{
	{langFR, "fr", "Français"},
	{langEN, "en", "English"},
	{langDE, "de", "Deutsch"},
	{langES, "es", "Español"},
	{langJA, "ja", "日本語"},
	{langKO, "ko", "한국어"},
	{langZH, "zh-CN", "简体中文"},
}

func isLang(code string) bool {
	for _, l := range languages {
		if l.Code == code {
			return true
		}
	}
	return false
}

// langTag is the <html lang> of a language code.
func langTag(code string) string {
	for _, l := range languages {
		if l.Code == code {
			return l.Tag
		}
	}
	return "fr"
}

// langPrimary is the primary subtag, the language a federation's metadata
// names an institution in ("zh" for zh-cn).
func langPrimary(code string) string {
	p, _, _ := strings.Cut(code, "-")
	return p
}

// lookup is the text of a key in a language.
func lookup(lang, key string) (string, bool) {
	switch lang {
	case langFR, langEN:
		s, ok := catalogue[key]
		i := 0
		if lang == langEN {
			i = 1
		}
		return s[i], ok && s[i] != ""
	}
	s, ok := translations[lang][key]
	return s, ok && s != ""
}

// translations are the texts of the languages after French and English, which
// are the columns of the catalogue: one file each (i18n_de.go ...).
var translations = map[string]map[string]string{
	langDE: catDE, langES: catES, langJA: catJA, langKO: catKO, langZH: catZH,
}

// catalogue is key -> {French, English}. Keys that start with "h." hold
// markup written here (never data): they are shown with th, the others are
// text and are escaped.
var catalogue = map[string][2]string{
	"skip": {"Aller au contenu", "Skip to content"},
	"help": {"Aide", "Help"},

	"lang.nav": {"Langue", "Language"},
	"lang.go":  {"Valider", "Apply"},

	"theme.nav":    {"Thème d'affichage", "Colour theme"},
	"theme.light":  {"Clair", "Light"},
	"theme.dark":   {"Sombre", "Dark"},
	"theme.system": {"Système", "System"},

	// Said by the script (passkey.js), which reads them from the page.
	"js.unsupported": {"Ce navigateur ne gère pas les clés d'accès.", "This browser does not support passkeys."},
	"js.invite":      {"Ouvrez le lien d'invitation en entier.", "Open the whole invitation link."},
	"js.cancelled":   {"Annulé, ou le délai est dépassé.", "Cancelled, or timed out."},
	"js.exists":      {"Cet appareil a déjà une clé d'accès pour ce compte.", "This device already has a passkey for this account."},
	"js.failed":      {"Échec : %s", "Failed: %s"},
	"js.registered":  {"Clé d'accès enregistrée. Vous pouvez fermer cette page.", "Passkey registered. You can close this page."},
	"js.waiting":     {"En attente de votre appareil…", "Waiting for your device…"},

	"msg.title": {"Connexion", "Sign in"},

	"home.title":   {"Service de connexion", "Sign-in service"},
	"home.p":       {"Ce service gère la connexion aux applications de %s : vous vous identifiez ici, une seule fois, puis vous retournez à l'application.", "This service signs you in to the applications of %s: you identify yourself here, once, then go back to the application."},
	"home.p.local": {"Les comptes locaux se connectent avec une clé d'accès : aucun mot de passe n'est tapé ni conservé.", "Local accounts sign in with a passkey: no password is ever typed or stored."},
	"home.account": {"Mon compte", "My account"},
	"home.fed":     {"Les personnes des établissements de la fédération %s peuvent se connecter avec leur établissement.", "People from the institutions of the %s federation can sign in with their own institution."},
	"home.links":   {"Applications", "Applications"},

	"choose.title":  {"Choisissez votre établissement", "Choose your institution"},
	"choose.ttl":    {"Choisir un établissement", "Choose an institution"},
	"choose.q":      {"Nom ou domaine", "Name or domain"},
	"choose.search": {"Rechercher", "Search"},
	"choose.none":   {"Aucun établissement ne correspond.", "No institution matches."},
	"choose.more":   {"%d autres : précisez la recherche.", "%d more: narrow the search."},

	"method.title":     {"Se connecter", "Sign in"},
	"method.fed":       {"Avec mon établissement", "With my institution"},
	"method.fed.sub":   {"Votre compte professionnel ou universitaire.", "Your work or university account."},
	"method.local":     {"Avec un compte local", "With a local account"},
	"method.local.sub": {"Une clé d'accès créée sur invitation.", "A passkey created from an invitation."},

	"login.title":  {"Compte local", "Local account"},
	"login.button": {"Se connecter avec une clé d'accès", "Sign in with a passkey"},
	"login.manage": {"Gérer mes clés d'accès", "Manage my passkeys"},

	"nojs.passkey": {"Une clé d'accès demande JavaScript.", "A passkey needs JavaScript."},
	"nojs.page":    {"Cette page demande JavaScript.", "This page needs JavaScript."},

	"enroll.title":  {"Enregistrer une clé d'accès", "Register a passkey"},
	"enroll.p":      {"Vous avez reçu une invitation d'un administrateur. Votre appareil va vous demander de créer une clé d'accès et de la déverrouiller (empreinte, visage ou code).", "An administrator invited you. Your device will ask you to create a passkey and unlock it (fingerprint, face or PIN)."},
	"enroll.button": {"Créer ma clé d'accès", "Create my passkey"},

	"device.title":    {"Connecter un appareil", "Connect a device"},
	"device.code":     {"Code affiché sur l'appareil", "Code shown on the device"},
	"device.err.rate": {"Trop d'essais. Réessayez dans quelques minutes.", "Too many attempts. Try again in a few minutes."},
	"device.err.code": {"Ce code n'est pas valide, ou a expiré.", "This code is not valid, or has expired."},
	"continue":        {"Continuer", "Continue"},

	"confirm.ttl":   {"Confirmer", "Confirm"},
	"confirm.title": {"%s demande à se connecter en votre nom", "%s is asking to sign in as you"},
	"confirm.code":  {"Code", "Code"},
	"h.confirm.warn": {
		"<strong>Ne continuez que si c'est vous qui avez lancé cette connexion, sur votre propre appareil.</strong> Si quelqu'un vous a transmis ce code, refusez : il obtiendrait l'accès à votre place.",
		"<strong>Only continue if you started this on your own device.</strong> If somebody sent you this code, refuse: they would get the access, not you."},
	"confirm.yes": {"Oui, c'est moi", "Yes, it is me"},
	"confirm.no":  {"Non", "No"},

	"open.wait": {"Un instant…", "One moment…"},

	"acct.title":    {"Mon compte", "My account"},
	"acct.done":     {"Terminer", "Done"},
	"acct.identity": {"Identité", "Identity"},
	"acct.login":    {"Identifiant", "Login"},
	"acct.name":     {"Nom", "Name"},
	"acct.mail":     {"Courriel", "Email"},
	"acct.groups":   {"Groupes", "Groups"},
	"acct.source":   {"Source", "Source"},
	"acct.src":      {"Compte local", "Local account"},
	"acct.note.local": {"Le courriel et les groupes sont modifiés par l'administrateur du service, pas ici.",
		"Email and groups are changed by the service's administrator, not here."},
	"acct.note.fed": {"Le courriel et les groupes sont modifiés par votre établissement, pas ici.",
		"Email and groups are changed by your institution, not here."},
	"acct.dispname": {"Nom affiché", "Display name"},
	"save":          {"Enregistrer", "Save"},

	"keys.title":    {"Clés d'accès", "Passkeys"},
	"keys.sub":      {"Chaque appareil garde sa propre clé : retirez celle d'un appareil perdu.", "Each device holds its own key: remove the one of a lost device."},
	"keys.created":  {"créée", "created"},
	"keys.lastused": {"dernière utilisation", "last used"},
	"keys.never":    {"jamais utilisée", "never used"},
	"keys.backup":   {"synchronisable", "backup-eligible"},
	"keys.current":  {"clé de cette confirmation", "this confirmation's key"},
	"keys.confirm":  {"Supprimer cette clé d'accès ?", "Remove this passkey?"},
	"keys.full":     {"Un compte a au plus %d clés : supprimez-en une pour en ajouter.", "At most %d passkeys: remove one to add another."},
	"keys.add":      {"Ajouter une clé d'accès", "Add a passkey"},
	"remove":        {"Supprimer", "Remove"},

	"apps.title":      {"Applications et sessions", "Applications and sessions"},
	"apps.opened":     {"ouverte", "opened"},
	"apps.never":      {"jamais renouvelée", "never renewed"},
	"apps.none":       {"Aucune.", "None."},
	"apps.confirm":    {"Mettre fin à cette session ?", "End this session?"},
	"apps.revokeall":  {"Tout révoquer", "Revoke all"},
	"apps.confirmall": {"Mettre fin à toutes les sessions ?", "End all sessions?"},
	"revoke":          {"Révoquer", "Revoke"},

	"access.kind.app_password": {"Mot de passe d'application", "Application password"},
	"access.kind.ssh":          {"Certificat SSH", "SSH certificate"},
	"access.kind.x509":         {"Certificat X.509", "X.509 certificate"},
	"access.kind.wireguard":    {"Clé WireGuard", "WireGuard key"},
	"access.title":             {"Accès techniques", "Technical access"},
	"access.expires":           {"expire", "expires"},
	"access.none":              {"Aucun.", "None."},
	"access.confirm":           {"Révoquer cet accès ?", "Revoke this access?"},

	"step.done.title": {"Session terminée", "Session ended"},
	"step.done.p":     {"Votre espace est fermé. Vous pouvez fermer cette page, ou vous reconnecter.", "Your account space is closed. You can close this page, or sign in again."},
	"step.p":          {"Confirmez que c'est vous : la confirmation dure cinq minutes.", "Confirm it is you: the confirmation lasts five minutes."},
	"step.passkey":    {"Confirmer avec ma clé d'accès", "Confirm with my passkey"},
	"step.fed":        {"Confirmer avec mon établissement", "Confirm with my institution"},

	"ph.summary":   {"Aide sur les clés d'accès", "Help with passkeys"},
	"ph.what.h":    {"Qu'est-ce qu'une clé d'accès ?", "What is a passkey?"},
	"ph.what.p":    {"C'est un moyen de se connecter sans rien taper : votre appareil la déverrouille avec votre empreinte, votre visage ou son code. Elle ne quitte jamais l'appareil et ne sert que sur ce service.", "A passkey signs you in without typing anything: your device unlocks it with your fingerprint, your face or its PIN. It never leaves the device and only works for this service."},
	"ph.dev.h":     {"Téléphone, ordinateur ou clé de sécurité", "Phone, computer or security key"},
	"h.ph.dev.1":   {"<strong>Ordinateur ou téléphone :</strong> validez avec l'empreinte, le visage ou le code de l'appareil. Si la clé est sur votre téléphone, choisissez « téléphone » dans la fenêtre du navigateur et scannez le code QR.", "<strong>Computer or phone:</strong> confirm with the device's fingerprint, face or PIN. If the passkey is on your phone, pick “phone” in the browser prompt and scan the QR code."},
	"h.ph.dev.2":   {"<strong>Clé de sécurité (USB, NFC) :</strong> insérez-la, puis <strong>touchez-la</strong> quand le navigateur le demande. Son code PIN, s'il existe, sera demandé.", "<strong>Security key (USB, NFC):</strong> plug it in, then <strong>touch it</strong> when the browser asks. Its PIN will be asked if it has one."},
	"ph.fail.h":    {"Si c'est refusé", "If it is refused"},
	"ph.fail.1":    {"« Annulé » ou « délai dépassé » : relancez, et répondez à la demande de l'appareil sans attendre.", "“Cancelled” or “timed out”: try again, and answer the device's prompt promptly."},
	"ph.fail.2":    {"Déverrouillez l'appareil, branchez ou approchez la clé ; pour un téléphone, activez le Bluetooth.", "Unlock the device, plug in or hold up the key; for a phone, turn Bluetooth on."},
	"ph.fail.3":    {"Essayez un autre navigateur à jour, ou l'appareil sur lequel la clé a été créée.", "Try another up-to-date browser, or the device the passkey was created on."},
	"ph.fail.pre":  {"Toujours bloqué ?", "Still stuck?"},
	"ph.support":   {"Contactez le support", "Contact support"},
	"ph.admin":     {"Contactez l'administrateur du service", "Contact the service's administrator"},
	"ph.fail.post": {"pour obtenir une nouvelle invitation.", "to get a new invitation."},
}

// dynamicKeys are the keys the Go code (not a template's literal) names.
func dynamicKeys() []string {
	var k []string
	for _, v := range pageTitles {
		k = append(k, v)
	}
	k = append(k, "device.err.rate", "device.err.code", "access.kind.app_password", "access.kind.ssh", "access.kind.x509", "access.kind.wireguard")
	sort.Strings(k)
	return k
}

// tmplFor is the template set of a language: the same files, with t, th and
// tf bound to it.
var tmplByLang = func() map[string]*template.Template {
	m := map[string]*template.Template{}
	for _, l := range languages {
		m[l.Code] = templatesFor(l.Code)
	}
	return m
}()

func templatesFor(l string) *template.Template {
	{
		text := func(key string) (string, error) {
			s, ok := lookup(l, key)
			if !ok {
				return "", fmt.Errorf("no %s text for %q", l, key)
			}
			return s, nil
		}
		return template.Must(template.New("").Funcs(template.FuncMap{
			"icon": icon,
			"t":    text,
			// tor is the text of a key, or the word itself when it is not one
			// (a certificate kind this page has no name for).
			"tor": func(key string) string {
				if s, ok := lookup(l, key); ok {
					return s
				}
				return key
			},
			"th": func(key string) (template.HTML, error) {
				if !strings.HasPrefix(key, "h.") {
					return "", fmt.Errorf("%q is text, not markup", key)
				}
				s, err := text(key)
				return template.HTML(s), err
			},
			// tf is a text with its numbers or names filled in; the result is
			// text, escaped like any other.
			"tf": func(key string, args ...any) (string, error) {
				s, err := text(key)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf(s, args...), nil
			},
		}).ParseFS(templateFS, "web/templates/*.html"))
	}
}

// ---- choosing the language ----

// langWriter carries the language and the theme chosen for the request, and
// the URL to come back to from the switches, to wherever a page is shown. It
// wraps the writer; Unwrap keeps http.ResponseController working. An empty
// theme is "system".
type langWriter struct {
	http.ResponseWriter
	lang, next, theme string
}

func (l *langWriter) Unwrap() http.ResponseWriter { return l.ResponseWriter }

func withLang(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(&langWriter{ResponseWriter: w, lang: chooseLang(r), next: r.URL.RequestURI(), theme: chooseTheme(r)}, r)
	})
}

// langOf is the language of the request a writer answers; French when there is
// none (a handler called without the middleware).
func langOf(w http.ResponseWriter) (lang, next string) {
	if l, ok := w.(*langWriter); ok && l.lang != "" {
		return l.lang, l.next
	}
	return langFR, "/"
}

// matchLang is the language of an Accept-Language range (lower case): the
// seven languages by their primary subtag, Chinese (zh, zh-CN, zh-Hans and the
// other zh-* tags, the only written Chinese there is here) as zh-cn.
func matchLang(tag string) (string, bool) {
	primary, _, _ := strings.Cut(tag, "-")
	if primary == "zh" {
		return langZH, true
	}
	if primary != langZH && isLang(primary) {
		return primary, true
	}
	return "", false
}

// chooseLang: the cookie, then Accept-Language (RFC 9110 12.5.4: the highest
// q, the first on a tie), then French.
func chooseLang(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && isLang(c.Value) {
		return c.Value
	}
	h := r.Header.Get("Accept-Language")
	if len(h) > 300 {
		h = h[:300]
	}
	best, bestQ := langFR, 0.0
	for _, part := range strings.Split(h, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		primary, ok := matchLang(tag)
		if !ok {
			continue
		}
		q := 1.0
		if p := strings.TrimSpace(params); strings.HasPrefix(strings.ToLower(p), "q=") {
			v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64)
			if err != nil || v < 0 || v > 1 {
				continue
			}
			q = v
		}
		if q > bestQ {
			best, bestQ = primary, q
		}
	}
	return best
}

// setLang is GET /lang?lang=<code>&next=/path (the combo's form) and GET
// /lang/{code}?next=/path: it sets the cookie and goes back to a path of this
// origin. The cookie is the choice and nothing else (SameSite=Lax, HttpOnly, a
// year); a next that is not a plain path on this origin is "/".
func (s *server) setLang(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		code = r.URL.Query().Get("lang")
	}
	if r.Method != http.MethodGet || !isLang(code) {
		http.NotFound(w, r)
		return
	}
	s.setPref(w, r, langCookie, code)
}

// setPref sets a preference cookie and goes back.
func (s *server) setPref(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: strings.HasPrefix(s.cfg.Issuer, "https://"),
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// ---- the theme ----

// The theme is light, dark or system (the default: the browser's
// prefers-color-scheme). It is chosen in the header, kept in the theme cookie
// (the choice and nothing else) and drawn by the SERVER: <html class="dark">
// or "light" is in the first byte of the page, so nothing flashes, and the
// buttons are a form (GET /theme) that works without script.
const (
	themeCookie = "theme"
	themeLight  = "light"
	themeDark   = "dark"
	themeSystem = "system"
)

var themes = []string{themeLight, themeDark, themeSystem}

func isTheme(v string) bool { return v == themeLight || v == themeDark || v == themeSystem }

// chooseTheme is the theme cookie when it is one of the three, else system.
func chooseTheme(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && isTheme(c.Value) {
		return c.Value
	}
	return themeSystem
}

// themeOf is the theme of the request a writer answers.
func themeOf(w http.ResponseWriter) string {
	if l, ok := w.(*langWriter); ok && isTheme(l.theme) {
		return l.theme
	}
	return themeSystem
}

// setTheme is GET /theme?theme=light|dark|system&next=/path.
func (s *server) setTheme(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("theme")
	if r.Method != http.MethodGet || !isTheme(v) {
		http.NotFound(w, r)
		return
	}
	s.setPref(w, r, themeCookie, v)
}

// safeNext is next when it is a path on this origin ("/x?y"), else "/".
func safeNext(next string) string {
	if len(next) == 0 || len(next) > 2000 || next[0] != '/' || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return next
}
