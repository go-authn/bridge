// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"errors"
	"testing"
	"time"
)

// ⛔ A row refused with an error no classifier knows (another driver, a
// custom code from a server-side trigger) must not keep the provider not
// ready for good, nor sit in front of the other rows: while the database
// takes other things and this row keeps failing, it is given up after a
// retry budget, like a classified permanent error. (#94)
func TestUnclassifiedPoisonRowIsGivenUpWhileOthersSucceed(t *testing.T) {
	f, _ := stateFixture(t)
	p := f.s.state
	clock := time.Now()
	p.now = func() time.Time { return clock }
	p.fail = func(kind, k string) error {
		if k == "poison" {
			return errors.New("ERROR 99999: refused by a trigger of its own")
		}
		return nil
	}
	var logged int
	p.logf = func(string, ...any) { logged++ }

	exp := time.Now().Add(time.Hour)
	if err := f.s.assertions.putNew("poison", true, exp); err != nil {
		t.Fatal(err)
	}
	if p.healthy() {
		t.Fatal("setup: the poison row should be unwritten")
	}
	// Later upserts persist, and the flushes they cause see the database
	// take them while the poison row fails.
	for i := range 10 {
		clock = clock.Add(10 * time.Second)
		if err := f.s.assertions.putNew("fine"+string(rune('a'+i)), true, exp); err != nil {
			t.Fatal(err)
		}
	}
	if !p.healthy() {
		t.Error("an unclassified poison row still keeps the provider not ready, while the database takes other rows")
	}
	if n := f.s.counters.get("bridge_state_rows_rejected_total")["write"]; n != 1 {
		t.Errorf("bridge_state_rows_rejected_total{kind=write} = %d, want 1", n)
	}
	before := logged
	for range 3 {
		p.healthy()
	}
	if logged != before {
		t.Error("a row given up is still being retried and logged")
	}
	f.restart(t)
	if f.s.assertions.putNew("fineb", true, exp) == nil {
		t.Error("a later upsert did not persist across a restart")
	}
}

// A database that is away takes nothing, so no row is at fault: nothing is
// given up however long it lasts, and the rows wait for it.
func TestNothingIsGivenUpWhileTheDatabaseIsDown(t *testing.T) {
	f, _ := stateFixture(t)
	p := f.s.state
	clock := time.Now()
	p.now = func() time.Time { return clock }
	p.logf = func(string, ...any) {}
	f.s.cfg.State.db.Close()

	exp := time.Now().Add(time.Hour)
	for i := range 5 {
		f.s.assertions.putNew("row"+string(rune('a'+i)), true, exp)
	}
	for range 50 {
		clock = clock.Add(time.Hour)
		if p.healthy() {
			t.Fatal("healthy with the database down")
		}
	}
	if n := f.s.counters.get("bridge_state_rows_rejected_total")["write"]; n != 0 {
		t.Errorf("%d rows given up during an outage", n)
	}
	p.mu.Lock()
	left := len(p.unwritten)
	p.mu.Unlock()
	if left != 5 {
		t.Errorf("%d rows waiting, want 5", left)
	}
}
