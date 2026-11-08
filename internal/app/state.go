// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
)

// What outlives a restart, with a state block: the refresh token families,
// the refresh tokens and the retired ones (reuse detection), and the access
// tokens this provider still honours at /userinfo and for SSH and X.509
// certificates. Without it, a restart logs everybody out -- and every
// ssh-oidc login, which motley-cue checks at /userinfo, fails until the
// person logs in again.
//
// Logins in progress, codes and device grants stay in memory: they live
// minutes, and a restart costs a retry.
//
// It is written through: every change goes to the database before the
// request is answered, and the database is read whole at start. Reads come
// from memory. So it is ONE process still -- two instances on one database
// would each miss what the other wrote since it started.
//
// ⛔ A refresh token is a credential; it is stored as its SHA-256, never as
// itself (fosite, Ory Hydra's core, stores a signature for the same reason):
// whoever reads the database cannot use what is in it. The token has 256
// random bits, so an unsalted hash is not guessable. Access tokens are
// stored by their jti, which is not a secret.
//
// ⛔ A revocation that the database did not take would come back at the next
// start. A delete that fails is kept and retried at every later write, and
// until it succeeds the provider is not ready (/readyz, the gRPC health).

type stateBlock struct {
	// Driver is sqlite, postgres or mysql; DSNFile holds the data source
	// name, which usually holds a password.
	Driver  string `hcl:"driver"`
	DSNFile string `hcl:"dsn_file"`

	db *sql.DB
}

func (b *stateBlock) check() error {
	if _, ok := sqlDrivers[b.Driver]; !ok {
		return fmt.Errorf("driver %q: sqlite, postgres or mysql", b.Driver)
	}
	dsn, err := os.ReadFile(b.DSNFile)
	if err != nil {
		return err
	}
	if b.db, err = sql.Open(sqlDrivers[b.Driver], strings.TrimSpace(string(dsn))); err != nil {
		return err
	}
	_, err = b.db.Exec(`CREATE TABLE IF NOT EXISTS bridge_state (
		kind    VARCHAR(32)  NOT NULL,
		k       VARCHAR(128) NOT NULL,
		v       TEXT         NOT NULL,
		expires BIGINT       NOT NULL,
		PRIMARY KEY (kind, k))`)
	return err
}

func (b *stateBlock) arg(n int) string {
	if b.Driver == "postgres" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// persister writes the stores through to the database.
type persister struct {
	b    *stateBlock
	logf func(string, ...any)
	// count adds one to a counter (the server's).
	count func(metric, label string)

	mu      sync.Mutex
	pending map[[2]string]bool // deletes the database has not taken yet
	// unwritten are writes the database has not taken yet. An SSF event
	// among them is a revocation no receiver hears of after a restart, so
	// they are retried like deletes, and the provider is not ready meanwhile.
	unwritten map[[2]string]pendingWrite
}

type pendingWrite struct {
	v       []byte
	expires time.Time
}

func (p *persister) put(kind, k string, v []byte, expires time.Time) error {
	tx, err := p.b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM bridge_state WHERE kind = `+p.b.arg(1)+` AND k = `+p.b.arg(2), kind, k); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO bridge_state (kind, k, v, expires) VALUES (`+
		p.b.arg(1)+`, `+p.b.arg(2)+`, `+p.b.arg(3)+`, `+p.b.arg(4)+`)`, kind, k, string(v), expires.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// del removes k, and remembers it if the database would not.
func (p *persister) del(kind, k string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.unwritten, [2]string{kind, k}) // gone before it was written
	if p.pending == nil {
		p.pending = map[[2]string]bool{}
	}
	p.pending[[2]string{kind, k}] = true
	p.flushLocked()
}

// flushLocked retries what the database has not taken. ⛔ The deletes are
// revocations, so a failed write never stops them: the writes stop at the
// first error that may be the database being away (retrying every row
// against a down database would cost a timeout each), then the deletes get
// their turn. A row refused for good is given up (reject), so it cannot sit
// at the front of every later flush. A DELETE has no value to refuse, so a
// delete that fails is always retried.
func (p *persister) flushLocked() {
	for key, w := range p.unwritten {
		err := p.put(key[0], key[1], w.v, w.expires)
		if err == nil {
			delete(p.unwritten, key)
			continue
		}
		if permanentDBError(err) {
			delete(p.unwritten, key)
			p.reject("write", key[0], key[1], err)
			continue
		}
		p.logf("state: writing %s %s: %v; retried at the next write, and not ready until then", key[0], key[1], err)
		break
	}
	for key := range p.pending {
		if _, err := p.b.db.Exec(`DELETE FROM bridge_state WHERE kind = `+p.b.arg(1)+` AND k = `+p.b.arg(2), key[0], key[1]); err != nil {
			p.logf("state: removing %s %s: %v; retried at the next write, and not ready until then", key[0], key[1], err)
			return
		}
		delete(p.pending, key)
	}
}

// permanentDBError says whether the database refused a row for good: the same
// statement would be refused again, whatever the connection. PostgreSQL
// SQLSTATE class 22 (data exception: a value too long, out of range) and 23
// (integrity constraint); MySQL's data-too-long, out-of-range, bad-value, null
// and key errors; SQLite's SQLITE_CONSTRAINT, SQLITE_MISMATCH and
// SQLITE_TOOBIG. Anything else -- a connection lost, a deadlock, a
// serialization failure, an error from a driver this does not know -- is
// retried: giving a row up is for errors known to be final.
func permanentDBError(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return strings.HasPrefix(pg.Code, "22") || strings.HasPrefix(pg.Code, "23")
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		switch my.Number {
		case 1048, // column cannot be null
			1062, // duplicate entry
			1264, // out of range
			1265, // data truncated
			1292, // truncated incorrect value
			1366, // incorrect value for column
			1406, // data too long
			1452: // foreign key
			return true
		}
		return false
	}
	var sq *sqlite.Error
	if errors.As(err, &sq) {
		switch sq.Code() & 0xff {
		case 18, 19, 20: // TOOBIG, CONSTRAINT, MISMATCH
			return true
		}
	}
	return false
}

// reject gives a row up that the database refuses for good: logged once,
// counted, and not retried. The value stays in memory, so the provider keeps
// honouring it until a restart; what is lost is only its persistence, and
// that is said.
func (p *persister) reject(op, kind, k string, err error) {
	p.logf("state: the database refuses %s %s for good (%v); giving it up -- it will not survive a restart (bridge_state_rows_rejected_total{kind=%q})", kind, k, err, op)
	p.count("bridge_state_rows_rejected_total", op)
}

// healthy is false while a revocation has not reached the database.
func (p *persister) healthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flushLocked()
	return len(p.pending) == 0 && len(p.unwritten) == 0
}

// load is every live row of kind.
func (p *persister) load(kind string, now time.Time) (map[string][]byte, map[string]time.Time, error) {
	if _, err := p.b.db.Exec(`DELETE FROM bridge_state WHERE expires <= `+p.b.arg(1), now.Unix()); err != nil {
		return nil, nil, err
	}
	rows, err := p.b.db.Query(`SELECT k, v, expires FROM bridge_state WHERE kind = `+p.b.arg(1), kind)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	vals, exps := map[string][]byte{}, map[string]time.Time{}
	for rows.Next() {
		var k, v string
		var exp int64
		if err := rows.Scan(&k, &v, &exp); err != nil {
			return nil, nil, err
		}
		vals[k], exps[k] = []byte(v), time.Unix(exp, 0)
	}
	return vals, exps, rows.Err()
}

// persistent is what a ttl needs to write itself through.
type persistent[V any] struct {
	p    *persister
	kind string
	enc  func(V) ([]byte, error)
	dec  func([]byte) (V, error)
}

// persist makes t write through to p, after loading what p holds.
func (t *ttl[V]) persist(p *persister, kind string, enc func(V) ([]byte, error), dec func([]byte) (V, error)) error {
	vals, exps, err := p.load(kind, t.now())
	if err != nil {
		return fmt.Errorf("state: reading %s: %w", kind, err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, raw := range vals {
		v, err := dec(raw)
		if err != nil {
			// A row that no longer means anything -- a client removed from
			// the configuration -- is dropped, not fatal.
			p.logf("state: dropping %s %s: %v", kind, k, err)
			p.del(kind, k)
			continue
		}
		t.m[k] = entry[V]{v, exps[k]}
	}
	t.store = &persistent[V]{p: p, kind: kind, enc: enc, dec: dec}
	return nil
}

func (t *ttl[V]) write(k string, v V, expires time.Time) {
	if t.store == nil {
		return
	}
	b, err := t.store.enc(v)
	if err == nil {
		err = t.store.p.put(t.store.kind, k, b, expires)
	}
	p := t.store.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if permanentDBError(err) {
		p.reject("write", t.store.kind, k, err)
		delete(p.unwritten, [2]string{t.store.kind, k})
		p.flushLocked()
		return
	}
	if err != nil {
		p.logf("state: writing %s %s: %v; retried at the next write, and not ready until then", t.store.kind, k, err)
		if p.unwritten == nil {
			p.unwritten = map[[2]string]pendingWrite{}
		}
		p.unwritten[[2]string{t.store.kind, k}] = pendingWrite{b, expires}
		return
	}
	delete(p.unwritten, [2]string{t.store.kind, k}) // a newer value is written
	p.flushLocked()
}

func (t *ttl[V]) forget(k string) {
	if t.store != nil {
		t.store.p.del(t.store.kind, k)
	}
}

// hashToken is what a refresh token is kept under: its SHA-256.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	// Into a buffer on the stack: one allocation, the string, where
	// EncodeToString made two (BenchmarkReplayUse).
	var b [43]byte // base64.RawURLEncoding.EncodedLen(sha256.Size)
	base64.RawURLEncoding.Encode(b[:], sum[:])
	return string(b[:])
}

// The codecs. person and refreshGrant keep their fields unexported; these
// are their stored forms.

type storedPerson struct {
	Subject    string         `json:"subject"`
	IdP        string         `json:"idp"`
	Username   string         `json:"username,omitempty"`
	Groups     []string       `json:"groups,omitempty"`
	AuthTime   time.Time      `json:"auth_time"`
	ACR        string         `json:"acr,omitempty"`
	SessionEnd time.Time      `json:"session_end,omitzero"`
	Profile    map[string]any `json:"profile,omitempty"`
	Email      map[string]any `json:"email,omitempty"`
	Edu        map[string]any `json:"edu,omitempty"`
}

func storePerson(p *person) storedPerson {
	return storedPerson{p.subject, p.idp, p.username, p.groups, p.authTime, p.acr, p.sessionEnd, p.profile, p.email, p.edu}
}

func (s storedPerson) person() *person {
	return &person{subject: s.Subject, idp: s.IdP, username: s.Username, groups: s.Groups, authTime: s.AuthTime,
		acr: s.ACR, sessionEnd: s.SessionEnd, profile: orEmpty(s.Profile), email: orEmpty(s.Email), edu: orEmpty(s.Edu)}
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

type storedRefresh struct {
	Client string       `json:"client"`
	Who    storedPerson `json:"who"`
	Scopes []string     `json:"scopes"`
	Family string       `json:"family"`
	Until  time.Time    `json:"until"`
	// Resources: RFC 8707. Absent in a state written before v0.21.0,
	// which means what it meant then: the client's whole audience.
	Resources []string `json:"resources,omitempty"`
}

type storedIssued struct {
	Info     map[string]any `json:"info"`
	Username string         `json:"username,omitempty"`
	IdP      string         `json:"idp,omitempty"`
	Subject  string         `json:"subject,omitempty"`
}

var errUnknownClient = errors.New("a client the configuration no longer has")

// persistStores writes the long-lived stores through to the state block.
func (s *server) persistStores() error {
	b := s.cfg.State
	if b == nil {
		return nil
	}
	s.state = &persister{b: b, logf: s.logf, count: s.counters.inc}
	if err := s.refresh.persist(s.state, "refresh",
		func(g *refreshGrant) ([]byte, error) {
			return json.Marshal(storedRefresh{g.client.ID, storePerson(g.who), g.scopes, g.family, g.until, g.resources})
		},
		func(b []byte) (*refreshGrant, error) {
			var r storedRefresh
			if err := json.Unmarshal(b, &r); err != nil {
				return nil, err
			}
			c, ok := s.cfg.client(r.Client)
			if !ok {
				return nil, errUnknownClient
			}
			return &refreshGrant{client: c, who: r.Who.person(), scopes: r.Scopes, resources: r.Resources, family: r.Family, until: r.Until}, nil
		}); err != nil {
		return err
	}
	if err := s.rotated.persist(s.state, "rotated", jsonEnc[string], jsonDec[string]); err != nil {
		return err
	}
	if err := s.families.persist(s.state, "family", jsonEnc[[]string], jsonDec[[]string]); err != nil {
		return err
	}
	// A login answered, and an assertion accepted, stay so across a restart:
	// the sealed login survives one, and must not be answered twice.
	if err := s.usedLogins.persist(s.state, "used-login", jsonEnc[bool], jsonDec[bool]); err != nil {
		return err
	}
	if err := s.assertions.persist(s.state, "assertion", jsonEnc[bool], jsonDec[bool]); err != nil {
		return err
	}
	if err := s.ssfStreams.persist(s.state, "ssf-stream", jsonEnc[storedStream], jsonDec[storedStream]); err != nil {
		return err
	}
	if err := s.ssfEvents.persist(s.state, "ssf-event", jsonEnc[string], jsonDec[string]); err != nil {
		return err
	}
	return s.issued.persist(s.state, "issued",
		func(it issuedToken) ([]byte, error) {
			return json.Marshal(storedIssued{it.info, it.username, it.idp, it.subject})
		},
		func(b []byte) (issuedToken, error) {
			var st storedIssued
			err := json.Unmarshal(b, &st)
			return issuedToken{info: st.Info, username: st.Username, idp: st.IdP, subject: st.Subject}, err
		})
}

func jsonEnc[V any](v V) ([]byte, error) { return json.Marshal(v) }

func jsonDec[V any](b []byte) (V, error) {
	var v V
	err := json.Unmarshal(b, &v)
	return v, err
}

// ttlReplay is go-authn/saml's Replay over a ttl, so that it is written
// through to the state database like the rest.
type ttlReplay struct{ t *ttl[bool] }

// Use keeps the assertion under the SHA-256 of what go-authn/saml names it
// by -- the IdP's entity ID and the assertion's ID, both the IdP's to choose
// and together longer than the state table's 128-character key allows: a
// row PostgreSQL or MySQL refuses stays unwritten and stops every later
// flush, revocations included (TestReplayKeyFitsTheStateTable).
func (r ttlReplay) Use(id string, expires time.Time) bool {
	return r.t.putNew(hashToken(id), true, expires) == nil
}
