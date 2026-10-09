package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// heldRequest starts a request whose body is held open: the handler checks
// the bearer token, then waits on the body. It returns once the handler has
// read the first byte -- after the token was accepted -- and finish sends the
// rest.
func heldRequest(t *testing.T, h http.Handler, path, token string, body []byte) (finish func() *httptest.ResponseRecorder) {
	t.Helper()
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, path, pr)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, req); close(done) }()
	if _, err := pw.Write(body[:1]); err != nil {
		t.Fatal(err)
	}
	return func() *httptest.ResponseRecorder {
		pw.Write(body[1:])
		pw.Close()
		<-done
		return w
	}
}

// unrevoked counts the certificates of a kind recorded and not revoked.
func unrevoked(f *fixture, kind string) int {
	f.s.certs.mu.Lock()
	defer f.s.certs.mu.Unlock()
	n := 0
	for _, c := range f.s.certs.Certs {
		if c.Kind == kind && c.Revoked.IsZero() {
			n++
		}
	}
	return n
}

// ⛔ A certificate request held open across a DisablePerson must not come
// back with a certificate. The token is checked when the request starts and
// the body read afterwards, at the client's pace; the certificate used to be
// signed and recorded after the disabling had already revoked everything,
// so no KRL or CRL listed it. Found by a security review.
func TestACertificateRequestHeldAcrossADisablingGetsNothing(t *testing.T) {
	for _, tc := range []struct {
		kind, client, scope, path string
		fixture                   func(*testing.T) *fixture
		body                      func(*testing.T) []byte
	}{
		{"ssh", "sftp", "ssh", "/ssh/certificate",
			func(t *testing.T) *fixture { f, _ := sshFixture(t); return f },
			func(t *testing.T) []byte { pub, _, _ := ed25519.GenerateKey(rand.Reader); return authorizedKey(t, pub) }},
		{"x509", "nfs", "nfs", "/x509/cert",
			func(t *testing.T) *fixture { f, _ := x509Fixture(t); return f },
			func(t *testing.T) []byte {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return csrFor(t, k)
			}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			f := tc.fixture(t)

			// The control: held open with nothing in between, it is issued.
			tok := f.deviceToken(tc.client, "openid", tc.scope)
			if w := heldRequest(t, f.s.handler(), tc.path, tok.AccessToken, tc.body(t))(); w.Code != http.StatusOK {
				t.Fatalf("a held request with no disabling: %d %s", w.Code, w.Body)
			}
			before := unrevoked(f, tc.kind)

			tok = f.deviceToken(tc.client, "openid", tc.scope)
			finish := heldRequest(t, f.s.handler(), tc.path, tok.AccessToken, tc.body(t))
			if _, _, err := f.s.disablePerson("alice@"+idpScope, "left", "test", time.Time{}); err != nil {
				t.Fatal(err)
			}
			if w := finish(); w.Code != http.StatusUnauthorized {
				t.Errorf("a request held across the disabling answered %d:\n%s", w.Code, w.Body)
			}
			if n := unrevoked(f, tc.kind); n != 0 {
				t.Errorf("%d %s certificates left unrevoked (the control's was %d before the disabling)", n, tc.kind, before)
			}
		})
	}
}
