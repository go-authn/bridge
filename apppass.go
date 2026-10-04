// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/directory"
)

// Application passwords: SMB and S3 cannot carry a token -- NTLMv2 and
// SigV4 prove a secret the server must already HOLD -- so somebody who logged
// in through their institution sets a password here, for those protocols
// only, and go-fileshare reads it from the same database with a `users
// "sql"` block.
//
// ⛔ What is stored is what the protocols need and no more. SMB needs the NT
// hash, which is password-EQUIVALENT (whoever holds it authenticates as the
// person) but reveals nothing reusable elsewhere. S3 needs the password
// itself. So `store` says which, and the default is the NT hash alone.

type appPasswordsBlock struct {
	// Driver is sqlite, postgres or mysql; DSNFile holds the data source
	// name, which usually holds a password.
	Driver  string `hcl:"driver"`
	DSNFile string `hcl:"dsn_file"`

	// Table is created if it does not exist: login, password, nt_hash,
	// expires (Unix seconds). "app_passwords" by default.
	Table string `hcl:"table,optional"`

	// Store is what to keep: "nt_hash" (SMB), "password" (S3, and anything
	// else that must hold the secret). ["nt_hash"] by default.
	Store []string `hcl:"store,optional"`

	// Lifetime is how long a password works: 90 days by default. The
	// federation is not asked in that time, so this is how long somebody who
	// has left keeps SMB and S3.
	Lifetime string `hcl:"lifetime,optional"`

	db       *sql.DB
	lifetime time.Duration
}

var sqlDrivers = map[string]string{"sqlite": "sqlite", "postgres": "pgx", "mysql": "mysql"}

func (b *appPasswordsBlock) check() error {
	if _, ok := sqlDrivers[b.Driver]; !ok {
		return fmt.Errorf("driver %q: sqlite, postgres or mysql", b.Driver)
	}
	if b.Table == "" {
		b.Table = "app_passwords"
	}
	// The table name goes into SQL text, so it is an identifier and nothing
	// else.
	for _, r := range b.Table {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return fmt.Errorf("table %q: lower-case letters, digits and _ only", b.Table)
		}
	}
	if len(b.Store) == 0 {
		b.Store = []string{"nt_hash"}
	}
	for _, s := range b.Store {
		if s != "nt_hash" && s != "password" {
			return fmt.Errorf("store %q: nt_hash or password", s)
		}
	}
	b.lifetime = 90 * 24 * time.Hour
	if b.Lifetime != "" {
		d, err := time.ParseDuration(b.Lifetime)
		if err != nil || d <= 0 {
			return fmt.Errorf("lifetime = %q: a positive duration like \"2160h\"", b.Lifetime)
		}
		b.lifetime = d
	}
	dsn, err := os.ReadFile(b.DSNFile)
	if err != nil {
		return err
	}
	if b.db, err = sql.Open(sqlDrivers[b.Driver], strings.TrimSpace(string(dsn))); err != nil {
		return err
	}
	_, err = b.db.Exec(`CREATE TABLE IF NOT EXISTS ` + b.Table + ` (
		login   VARCHAR(255) NOT NULL PRIMARY KEY,
		password VARCHAR(255),
		nt_hash  VARCHAR(32),
		expires  BIGINT NOT NULL,
		idp      VARCHAR(1024))`)
	if err != nil {
		return err
	}
	// A table from before the idp column: add it. Its rows keep a NULL
	// there, and removeIdP finds them by scope instead.
	if _, err := b.db.Exec(`SELECT idp FROM ` + b.Table + ` WHERE 1 = 0`); err != nil {
		if _, err := b.db.Exec(`ALTER TABLE ` + b.Table + ` ADD COLUMN idp VARCHAR(1024)`); err != nil {
			return fmt.Errorf("adding the idp column to %s: %w", b.Table, err)
		}
	}
	return nil
}

// arg is the n-th placeholder in this driver's dialect.
func (b *appPasswordsBlock) arg(n int) string {
	if b.Driver == "postgres" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// set replaces a person's application password; idp is the institution
// that vouched for them, so that disabling it can find the password.
func (b *appPasswordsBlock) set(login, idp, password string, expires time.Time) error {
	var pw, nt sql.NullString
	if slices.Contains(b.Store, "password") {
		pw = sql.NullString{String: password, Valid: true}
	}
	if slices.Contains(b.Store, "nt_hash") {
		nt = sql.NullString{String: hex.EncodeToString(directory.NTHashOf(password)), Valid: true}
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM `+b.Table+` WHERE LOWER(login) = LOWER(`+b.arg(1)+`)`, login); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO `+b.Table+` (login, password, nt_hash, expires, idp) VALUES (`+
		b.arg(1)+`, `+b.arg(2)+`, `+b.arg(3)+`, `+b.arg(4)+`, `+b.arg(5)+`)`, login, pw, nt, expires.Unix(), idp); err != nil {
		return err
	}
	return tx.Commit()
}

// remove deletes a person's application password.
func (b *appPasswordsBlock) remove(login string) error {
	_, err := b.removeCount(login)
	return err
}

// removeCount deletes a person's application password and says how many
// there were.
func (b *appPasswordsBlock) removeCount(login string) (int64, error) {
	// Without case, as usernames are disabled (normUsername) and as set()
	// replaces a row: a row kept as the IdP spelled it, "Alice@...", survived
	// disabling "alice@..." -- and with it, SMB and S3.
	res, err := b.db.Exec(`DELETE FROM `+b.Table+` WHERE LOWER(login) = LOWER(`+b.arg(1)+`)`, login)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// removeIdP deletes the application passwords of the people one institution
// vouched for: those recorded with it, and those from before the idp column
// whose login is in one of scopes -- which only a scoped username (eppn,
// subject-id) is, and which go-authn/saml has already held to the scopes
// the federation grants that IdP. It says how many it removed.
func (b *appPasswordsBlock) removeIdP(entityID string, scopes []string) (int64, error) {
	res, err := b.db.Exec(`DELETE FROM `+b.Table+` WHERE idp = `+b.arg(1), entityID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if len(scopes) == 0 {
		return n, nil
	}
	rows, err := b.db.Query(`SELECT login FROM ` + b.Table + ` WHERE idp IS NULL`)
	if err != nil {
		return n, err
	}
	var logins []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			rows.Close()
			return n, err
		}
		if _, scope, ok := strings.Cut(l, "@"); ok && slices.Contains(scopes, scope) {
			logins = append(logins, l)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return n, err
	}
	for _, l := range logins {
		m, err := b.removeCount(l)
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

// passwordAlphabet has no characters that read alike (0/O, 1/l/I) and none
// that a shell or a URL would want quoted.
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newAppPassword is 24 characters from passwordAlphabet: about 139 bits.
func newAppPassword() string {
	b := make([]byte, 24)
	n := big.NewInt(int64(len(passwordAlphabet)))
	for i := range b {
		k, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic(err)
		}
		b[i] = passwordAlphabet[k.Int64()]
	}
	return string(b)
}

// appPassword sets (POST) or removes (DELETE) the application password of
// the person the bearer token is about. The password is generated here and
// shown once: a password somebody chose is a password they use elsewhere.
func (s *server) appPassword(w http.ResponseWriter, r *http.Request) {
	ap := s.cfg.AppPasswords
	if ap == nil {
		http.NotFound(w, r)
		return
	}
	claims, err := s.bearerClaims(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "the token is not valid", http.StatusUnauthorized)
		return
	}
	clientID, _ := claims["client_id"].(string)
	client, ok := s.cfg.client(clientID)
	scope, _ := claims["scope"].(string)
	if !ok || !client.AppPasswords || !slices.Contains(strings.Fields(scope), "app_password") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="app_password"`)
		http.Error(w, "this token may not set application passwords", http.StatusForbidden)
		return
	}
	if !s.addressedHere(claims) {
		notAddressedHere(w)
		return
	}
	user, _ := claims["preferred_username"].(string)
	if user == "" {
		http.Error(w, "the institution released no username to set a password for", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := ap.remove(user); err != nil {
			s.logf("app password: %v", err)
			http.Error(w, "the password could not be removed", http.StatusInternalServerError)
			return
		}
		s.logf("app password: removed for %s", user)
		s.counters.inc("bridge_app_passwords_total", "removed")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPost:
		pw := newAppPassword()
		exp := s.now().Add(ap.lifetime)
		jti, _ := claims["jti"].(string)
		it, _ := s.issued.get(jti)
		if err := ap.set(user, it.idp, pw, exp); err != nil {
			s.logf("app password: %v", err)
			http.Error(w, "the password could not be stored", http.StatusInternalServerError)
			return
		}
		// A disabling that arrived while this was being set: it is recorded
		// before anything is revoked, so either its revocation removed the
		// password or this sees it.
		if why := s.refused(&person{username: user, idp: it.idp}); why != "" {
			ap.remove(user)
			http.Error(w, "the token is not valid", http.StatusUnauthorized)
			return
		}
		s.counters.inc("bridge_app_passwords_total", "set")
		s.logf("app password: set for %s until %s", user, exp.UTC().Format(time.RFC3339))
		writeJSON(w, http.StatusOK, map[string]any{"username": user, "password": pw, "expires": exp.Unix()})
	default:
		http.Error(w, "POST or DELETE", http.StatusMethodNotAllowed)
	}
}
