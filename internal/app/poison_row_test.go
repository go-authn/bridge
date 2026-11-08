// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

// ⛔ One row the database refuses for good must not stop the flush: the
// pending deletes behind it are revocations. The database refuses the key
// "poison" through a trigger (a real constraint error, SQLITE_CONSTRAINT);
// then a token is revoked, and the revocation must be in the database after
// a restart. The poison row is logged once, counted, and not retried;
// /readyz is ready again.
func TestPoisonRowDoesNotStopRevocations(t *testing.T) {
	f, _ := stateFixture(t)
	db := f.s.cfg.State.db
	if _, err := db.Exec(`CREATE TRIGGER poison BEFORE INSERT ON bridge_state WHEN NEW.k = 'poison'
		BEGIN SELECT RAISE(ABORT, 'refused for good'); END`); err != nil {
		t.Skipf("the trigger needs SQLite: %v", err)
	}
	var logged int
	f.s.state.logf = func(format string, args ...any) { logged++ }

	tok := f.deviceToken("rclone", "openid")
	if err := f.s.assertions.putNew("poison", true, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.revokePerson("alice@" + idpScope); err != nil {
		t.Fatal(err)
	}

	f.restart(t)
	if s := f.userinfoStatus(t, tok.AccessToken); s != http.StatusUnauthorized {
		t.Errorf("a revocation queued behind a row the database refuses for good: /userinfo after a restart: %d", s)
	}
	if _, err := f.refreshWith(t, tok.RefreshToken); err == nil {
		t.Error("a revoked refresh token came back with the restart, behind a poison row")
	}
}

func TestPoisonRowIsReportedOnceAndCounted(t *testing.T) {
	f, _ := stateFixture(t)
	if _, err := f.s.cfg.State.db.Exec(`CREATE TRIGGER poison BEFORE INSERT ON bridge_state WHEN NEW.k = 'poison'
		BEGIN SELECT RAISE(ABORT, 'refused for good'); END`); err != nil {
		t.Skipf("the trigger needs SQLite: %v", err)
	}
	var logged int
	f.s.state.logf = func(format string, args ...any) { logged++ }

	if err := f.s.assertions.putNew("poison", true, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for range 3 { // later flushes must not retry it
		f.s.state.healthy()
	}
	if logged != 1 {
		t.Errorf("the poison row was logged %d times, want once", logged)
	}
	if n := f.s.counters.get("bridge_state_rows_rejected_total")["write"]; n != 1 {
		t.Errorf("bridge_state_rows_rejected_total{kind=write} = %d, want 1", n)
	}
	if !f.s.state.healthy() {
		t.Error("a row given up on keeps the provider not ready")
	}

	// A write queued while the database was away, refused for good once it
	// is back: the flush gives it up too, once.
	p := f.s.state
	p.mu.Lock()
	p.unwritten = map[[2]string]pendingWrite{{"assertion", "poison"}: {[]byte("true"), time.Now().Add(time.Hour)}}
	p.mu.Unlock()
	logged = 0
	p.healthy()
	p.healthy()
	if logged != 1 || !p.healthy() {
		t.Errorf("a queued poison row: logged %d times, want once; healthy %v", logged, p.healthy())
	}
	if n := f.s.counters.get("bridge_state_rows_rejected_total")["write"]; n != 2 {
		t.Errorf("bridge_state_rows_rejected_total{kind=write} = %d, want 2", n)
	}
}

// The driver error classes: a refusal that no retry changes, against what
// does (PostgreSQL SQLSTATE class 22 and 23; MySQL 1406, 1062, ...; SQLite
// SQLITE_CONSTRAINT).
func TestPermanentDBError(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&pgconn.PgError{Code: "22001"}, true},   // string_data_right_truncation
		{&pgconn.PgError{Code: "23505"}, true},   // unique_violation
		{&pgconn.PgError{Code: "40001"}, false},  // serialization_failure: retry
		{&pgconn.PgError{Code: "57P01"}, false},  // admin_shutdown
		{&mysql.MySQLError{Number: 1406}, true},  // data too long
		{&mysql.MySQLError{Number: 1062}, true},  // duplicate entry
		{&mysql.MySQLError{Number: 1213}, false}, // deadlock: retry
		{&mysql.MySQLError{Number: 2006}, false}, // server has gone away
		{errors.New("connection refused"), false},
		{nil, false},
	} {
		if got := permanentDBError(c.err); got != c.want {
			t.Errorf("permanentDBError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
	// The SQLite case is the trigger test above, on a real error.
}
