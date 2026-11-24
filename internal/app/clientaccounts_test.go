package app

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/webauthn"
	"github.com/go-authn/webauthn/webauthntest"
	"golang.org/x/oauth2"
)

// accounts = ["local"] / ["federated"]: which kind of account a client takes.
// The rule is held at every place a grant is made or used, so each test here
// puts a person of the wrong kind at ONE of them, with everything before it
// let through, and a mutant that removes that one check must fail it.

func restrict(f *fixture, id string, accounts ...string) {
	f.t.Helper()
	c, ok := f.s.cfg.client(id)
	if !ok {
		f.t.Fatalf("no client %q", id)
	}
	c.Accounts = accounts
}

// With nobody to judge, or no client to judge against, there is nothing to
// refuse: each missing half is tried alone, so neither nil check can go.
func TestClientAccountsNothingToJudge(t *testing.T) {
	s := &server{}
	judge := func(name string, c *clientBlock, p *person) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: panicked: %v", name, r)
			}
		}()
		if got := s.accountsRefused(c, p); got != "" {
			t.Errorf("%s: %q", name, got)
		}
	}
	judge("no client", nil, &person{})
	judge("no person", &clientBlock{Accounts: []string{"local"}}, nil)
}

func TestClientAccountsConfig(t *testing.T) {
	for _, c := range []struct {
		name     string
		accounts []string
		local    bool
		wantErr  string
	}{
		{"absent", nil, false, ""},
		{"local", []string{"local"}, true, ""},
		{"federated", []string{"federated"}, false, ""},
		{"both", []string{"local", "federated"}, true, ""},
		{"empty", []string{}, true, "nobody could sign in"},
		{"unknown", []string{"ldap"}, true, `"ldap" is not`},
		{"twice", []string{"local", "local"}, true, "twice"},
		{"local without a local block", []string{"local"}, false, "no local block"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := (&clientBlock{Accounts: c.accounts}).checkAccounts(c.local)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("got %v, want an error with %q", err, c.wantErr)
			}
		})
	}
	for accounts, want := range map[string]string{"": "local and federated accounts", "local": "local accounts only", "federated": "federated accounts only"} {
		cl := &clientBlock{}
		if accounts != "" {
			cl.Accounts = []string{accounts}
		}
		if got := cl.accountsLine(); got != want {
			t.Errorf("accounts %q: line %q, want %q", accounts, got, want)
		}
	}
}

// The rule is part of loading a configuration, not only of the method: a
// restriction nobody checks at load is one that fails at the first login.
func TestClientAccountsRefusedAtLoad(t *testing.T) {
	c := newConf(t)
	client := func(body string) string {
		return c.hcl(nil) + "client \"p\" {\ndevice = true\n" + body + "\n}\n"
	}
	if _, err := c.load(t, client(`accounts = ["ldap"]`)); err == nil || !strings.Contains(err.Error(), `client "p"`) || !strings.Contains(err.Error(), `"ldap" is not`) {
		t.Errorf("an unknown kind: %v", err)
	}
	if _, err := c.load(t, client(`accounts = ["federated"]`)); err != nil {
		t.Errorf("accounts = [federated] refused: %v", err)
	}
}

func TestClientAccountsRoutesTheLoginToTheKindItTakes(t *testing.T) {
	f := localFixture(t, "")
	web := func() string {
		return newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile").authURL()
	}
	for _, c := range []struct {
		name     string
		accounts []string
		path     string
	}{
		{"both are offered the choice", nil, "/login"},
		{"local only goes to the passkey page", []string{"local"}, "/local/login"},
		{"federated only goes to the federation", []string{"federated"}, "/saml/choose"},
	} {
		t.Run(c.name, func(t *testing.T) {
			restrict(f, "web", c.accounts...)
			if got := location(t, newBrowser(t).get(web())); got.Path != c.path {
				t.Errorf("sent to %s, want %s", got, c.path)
			}
		})
	}

	t.Run("prompt=none for a local-only client has nothing to ask", func(t *testing.T) {
		restrict(f, "web", "local")
		r := newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile")
		back := location(t, newBrowser(t).get(r.authURL(oauth2.SetAuthURLParam("prompt", "none"))))
		if back.Query().Get("error") != "login_required" || back.Query().Get("code") != "" {
			t.Errorf("answered %s, want login_required", back)
		}
	})
}

func accessDenied(t *testing.T, err error) {
	t.Helper()
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) || re.ErrorCode != "access_denied" {
		t.Fatalf("got %v, want the token endpoint's access_denied", err)
	}
}

// aliceViaFederation walks a federated person to the IdP and returns what the
// ACS post needs; nothing is decided yet.
func (f *fixture) toTheIdP(b *browser, authURL string) (reqID, relay string) {
	f.t.Helper()
	b.get(authURL)
	next := location(f.t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
	return authnRequest(f.t, next)
}

// fedLogin is the whole federated login, whatever page comes first.
func (f *fixture) fedLogin(authURL string) *url.URL {
	f.t.Helper()
	b := newBrowser(f.t)
	reqID, relay := f.toTheIdP(b, authURL)
	return location(f.t, b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}}))
}

// A client authenticated in the header: x/oauth2 otherwise retries a refused
// request with the secret in the body, and the retry meets a spent code.
func headerAuth(r *rp) *rp {
	r.cfg.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return r
}

func TestFederatedPersonRefusedByALocalOnlyClient(t *testing.T) {
	newF := func(t *testing.T) (*fixture, *rp, *bytes.Buffer) {
		f := localFixture(t, localClients)
		var logs bytes.Buffer
		f.s.log = &logs
		web, _ := f.s.cfg.client("web")
		web.refreshTTL = time.Hour
		return f, headerAuth(newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile")), &logs
	}

	t.Run("the federation path itself is closed", func(t *testing.T) {
		f, r, logs := newF(t)
		restrict(f, "web", "local")
		b := newBrowser(t)
		b.get(r.authURL()) // the login cookie of a local-only client
		back := location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
		if back.Host == idpScope || back.Query().Get("error") != "access_denied" {
			t.Errorf("sent to %s, want the client with access_denied, not the IdP", back)
		}
		logLine(t, logs.String(), `^login: a federated sign-in was started for web, which takes local accounts only$`)
	})

	t.Run("the end of the login", func(t *testing.T) {
		f, r, logs := newF(t)
		b := newBrowser(t)
		reqID, relay := f.toTheIdP(b, r.authURL()) // the path was open when it started
		restrict(f, "web", "local")
		back := location(t, b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}}))
		if back.Query().Get("error") != "access_denied" || back.Query().Get("code") != "" {
			t.Fatalf("answered %s, want access_denied and no code", back)
		}
		logLine(t, logs.String(), `^login: alice@`+idpScope+` via `+idpEntity+` refused for web: this client takes local accounts only$`)
		noneOf(t, logs.String(), map[string]string{"name": "Alice Martin", "SAMLResponse": "PHNhbWw"})
	})

	t.Run("the code exchange", func(t *testing.T) {
		f, r, _ := newF(t)
		back := f.fedLogin(r.authURL()) // a code, bought while the client took both
		restrict(f, "web", "local")
		_, err := r.cfg.Exchange(t.Context(), back.Query().Get("code"), oauth2.VerifierOption(r.verifier))
		accessDenied(t, err)
	})

	t.Run("the refresh", func(t *testing.T) {
		f, r, _ := newF(t)
		tok, err := r.cfg.Exchange(t.Context(), f.fedLogin(r.authURL()).Query().Get("code"), oauth2.VerifierOption(r.verifier))
		if err != nil || tok.RefreshToken == "" {
			t.Fatalf("setup: %v, refresh token %q", err, tok.RefreshToken)
		}
		restrict(f, "web", "federated") // the control: a restriction that keeps this person
		tok, err = r.cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		if err != nil {
			t.Fatalf("a federated person is refused by a client that takes federated accounts: %v", err)
		}
		restrict(f, "web", "local")
		_, err = r.cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		accessDenied(t, err)
	})

	t.Run("the device poll", func(t *testing.T) {
		f, _, _ := newF(t)
		b, cfg, da, next := f.deviceStart("files", "openid")
		if next.Path != "/login" {
			t.Fatalf("sent to %s", next)
		}
		next = location(t, b.get(f.s.cfg.Issuer+"/saml/disco?entityID="+idpEntity))
		reqID, relay := authnRequest(t, next)
		b.post(f.s.cfg.Issuer+"/saml/acs", map[string][]string{"SAMLResponse": {f.respond(reqID, alice)}, "RelayState": {relay}})
		restrict(f, "files", "local")
		_, err := cfg.DeviceAccessToken(t.Context(), da)
		accessDenied(t, err)
	})

	t.Run("the device login", func(t *testing.T) {
		f, _, _ := newF(t)
		restrict(f, "files", "local")
		b, cfg, da, next := f.deviceStart("files", "openid")
		if next.Path != "/local/login" {
			t.Fatalf("a device login for a local-only client was sent to %s", next)
		}
		back := b.get(f.s.cfg.Issuer + "/saml/disco?entityID=" + idpEntity)
		if back.StatusCode != http.StatusForbidden {
			// Fatal: the poll below would wait for an approval that never comes.
			t.Fatalf("the federation step for a local-only device client answered %d, want 403", back.StatusCode)
		}
		_, err := cfg.DeviceAccessToken(t.Context(), da)
		accessDenied(t, err)
	})
}

func TestLocalAccountTakenByALocalOnlyClientAndRefusedByAFederatedOnlyOne(t *testing.T) {
	newF := func(t *testing.T) (*fixture, *rp, *webauthntest.Authenticator) {
		f := localFixture(t, localClients)
		web, _ := f.s.cfg.client("web")
		web.refreshTTL = time.Hour
		return f, headerAuth(newRP(t, f, "web", "a-secret-long-enough-to-pass", f.redirect, "profile")), f.enrolled("alice", webauthn.AlgES256)
	}
	signIn := func(t *testing.T, f *fixture, r *rp, a *webauthntest.Authenticator) string {
		b := newBrowser(t)
		csrf := f.localForm(func() *browser { b.get(r.authURL()); return b }())
		return location(t, f.passkeyLogin(b, a, "alice", csrf, webauthntest.Options{})).Query().Get("code")
	}

	t.Run("a local-only client takes the whole grant", func(t *testing.T) {
		f, r, a := newF(t)
		restrict(f, "web", "local")
		tok, err := r.cfg.Exchange(t.Context(), signIn(t, f, r, a), oauth2.VerifierOption(r.verifier))
		if err != nil {
			t.Fatalf("the control: a local account on a local-only client: %v", err)
		}
		if _, err := r.cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err != nil {
			t.Fatalf("the control's refresh: %v", err)
		}
	})

	t.Run("the local sign-in step of a federated-only client", func(t *testing.T) {
		f, r, _ := newF(t)
		restrict(f, "web", "federated")
		b := newBrowser(t)
		b.get(r.authURL())
		back := location(t, b.get(f.s.cfg.Issuer+"/local/login"))
		if back.Query().Get("error") != "access_denied" {
			t.Errorf("the passkey page answered %s, want the client with access_denied", back)
		}
	})

	t.Run("the code exchange", func(t *testing.T) {
		f, r, a := newF(t)
		code := signIn(t, f, r, a)
		restrict(f, "web", "federated")
		_, err := r.cfg.Exchange(t.Context(), code, oauth2.VerifierOption(r.verifier))
		accessDenied(t, err)
	})

	t.Run("the refresh", func(t *testing.T) {
		f, r, a := newF(t)
		tok, err := r.cfg.Exchange(t.Context(), signIn(t, f, r, a), oauth2.VerifierOption(r.verifier))
		if err != nil {
			t.Fatal(err)
		}
		restrict(f, "web", "federated")
		_, err = r.cfg.TokenSource(t.Context(), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		accessDenied(t, err)
	})
}
