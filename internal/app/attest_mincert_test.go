// SPDX-License-Identifier: BSD-3-Clause

package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/fido/mds"
)

// reportsEntry is an entry shaped like the real BLOB's, with a certification
// history: yubikeyBio is the YubiKey Bio, certified L1 in 2021 and L2 in 2022.
func (m *testMDS) reportsEntry(aaguid string, reports ...[2]string) string {
	var rs []map[string]string
	for _, r := range reports {
		rs = append(rs, map[string]string{"status": r[0], "effectiveDate": r[1]})
	}
	b, err := json.Marshal(map[string]any{
		"aaguid":            aaguid,
		"metadataStatement": map[string]any{"description": "YubiKey Bio"},
		"statusReports":     rs,
	})
	if err != nil {
		m.t.Fatal(err)
	}
	return string(b)
}

var (
	bioHistory = [][2]string{
		{"FIDO_CERTIFIED", "2020-05-01"}, {"FIDO_CERTIFIED_L1", "2021-04-02"}, {"FIDO_CERTIFIED_L2", "2022-03-01"},
	}
	l1History     = [][2]string{{"FIDO_CERTIFIED", "2020-05-01"}, {"FIDO_CERTIFIED_L1", "2021-04-02"}}
	l3History     = [][2]string{{"FIDO_CERTIFIED_L1", "2021-04-02"}, {"FIDO_CERTIFIED_L3", "2023-01-10"}}
	legacyHistory = [][2]string{{"FIDO_CERTIFIED", "2020-05-01"}}
	revokedAfter  = append(append([][2]string{}, bioHistory...), [2]string{"REVOKED", "2024-02-01"})
)

func TestAdminMinCertificationIsCheckedWhereTheEntryIsResolved(t *testing.T) {
	now := func() time.Time { return time.Now().UTC() }
	for _, c := range []struct {
		name    string
		min     mds.Level
		history [][2]string
		wantErr string
	}{
		{"unset: no check, even without any level", mds.LevelNone, legacyHistory, ""},
		{"unset: no check, no reports", mds.LevelNone, nil, ""},
		{"L1 only, minimum L2: refused", mds.L2, l1History, "certification level of L1, below admin_min_certification L2"},
		{"L2, minimum L2: accepted", mds.L2, bioHistory, ""},
		{"L2, minimum L1: accepted", mds.L1, bioHistory, ""},
		{"L2, minimum L2plus: refused", mds.L2plus, bioHistory, "below"},
		{"L3, minimum L2: accepted", mds.L2, l3History, ""},
		{"L3, minimum L3: accepted", mds.L3, l3History, ""},
		{"L3, minimum L3plus: refused", mds.L3plus, l3History, "below"},
		{"no certification report: refused", mds.L1, nil, "level of none"},
		{"only the legacy FIDO_CERTIFIED: refused", mds.L1, legacyHistory, "level of none"},
		{"REVOKED after L2: refused", mds.L2, revokedAfter, "REVOKED"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newTestMDS(t, now)
			m.set(m.reportsEntry(yubikeyBio, c.history...))
			v := m.verifier(t, t.TempDir(), t.Logf)
			v.minCert = c.min
			m.load(v)
			err := v.stillTrusted(yubikeyBio)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("%v, want it to say %q", err, c.wantErr)
			}
		})
	}
}

// A model downgraded, or revoked, after a key was proved loses the page at the
// next use: stillTrusted reads the blob as it is now.
func TestAModelDowngradedLaterIsNoLongerTrusted(t *testing.T) {
	now := func() time.Time { return time.Now().UTC() }
	m := newTestMDS(t, now)
	m.set(m.reportsEntry(yubikeyBio, bioHistory...))
	v := m.verifier(t, t.TempDir(), t.Logf)
	v.minCert = mds.L2
	m.load(v)
	if err := v.stillTrusted(yubikeyBio); err != nil {
		t.Fatal(err)
	}
	m.set(m.reportsEntry(yubikeyBio, append(append([][2]string{}, bioHistory...), [2]string{"FIDO_CERTIFIED_L1", "2025-01-01"})...))
	m.load(v)
	if err := v.stillTrusted(yubikeyBio); err == nil || !strings.Contains(err.Error(), "below") {
		t.Errorf("a re-certification at L1 still passes L2: %v", err)
	}
}

// At registration a key whose model is below the minimum is stored, signs in,
// and is simply not proven: it never opens the administrator page.
func TestAKeyBelowTheMinimumIsStoredWithoutAProvenModel(t *testing.T) {
	e := newAdminEnv(t)
	e.s.attest.minCert = mds.L2
	e.mds.set(e.mds.reportsEntryWithRoot(yubikeyBio, e.attCA.cert.Raw, l1History...))
	e.mds.load(e.s.attest)
	st, attested, _, a := e.enrolAs("carol", e.attestedBy(e.attCA, yubikeyBio))
	if st != http.StatusOK || attested {
		t.Fatalf("status %d, attested %v", st, attested)
	}
	if got := e.provenModel(a); got != "" {
		t.Errorf("the key is marked proven: %q", got)
	}
	if !strings.Contains(e.log(), "below admin_min_certification L2") {
		t.Errorf("the log does not say why:\n%s", e.log())
	}
	e.mds.set(e.mds.reportsEntryWithRoot(yubikeyBio, e.attCA.cert.Raw, bioHistory...))
	e.mds.load(e.s.attest)
	st, attested, _, _ = e.enrolAs("carol", e.attestedBy(e.attCA, yubikeyBio))
	if st != http.StatusOK || !attested {
		t.Fatalf("an L2 model: status %d, attested %v", st, attested)
	}
}

func (m *testMDS) reportsEntryWithRoot(aaguid string, rootDER []byte, reports ...[2]string) string {
	var rs []map[string]string
	for _, r := range reports {
		rs = append(rs, map[string]string{"status": r[0], "effectiveDate": r[1]})
	}
	b, err := json.Marshal(map[string]any{
		"aaguid":            aaguid,
		"metadataStatement": map[string]any{"description": "YubiKey Bio", "attestationRootCertificates": []string{base64.StdEncoding.EncodeToString(rootDER)}},
		"statusReports":     rs,
	})
	if err != nil {
		m.t.Fatal(err)
	}
	return string(b)
}

func TestAdminMinCertificationConfig(t *testing.T) {
	path := writeAccountsFile(t, adminAccountsText())
	st, err := newLocalStore(path, localScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	withMail := &config{Mail: &mailBlock{}}
	adm := func(min string) localBlock {
		return localBlock{Admins: []string{"alice"}, AdminAAGUIDs: []string{yubikeyBio}, AdminMinCertification: min}
	}
	for _, c := range []struct {
		min     string
		want    mds.Level
		wantErr string
	}{
		{"", mds.LevelNone, ""},
		{"L1", mds.L1, ""}, {"L1plus", mds.L1plus, ""}, {"L2", mds.L2, ""},
		{"L2plus", mds.L2plus, ""}, {"L3", mds.L3, ""}, {"L3plus", mds.L3plus, ""},
		{"l2", 0, "admin_min_certification"}, {"L4", 0, "admin_min_certification"},
		{"FIDO_CERTIFIED_L2", 0, "admin_min_certification"}, {"L2+", 0, "admin_min_certification"},
		{" L2", 0, "admin_min_certification"},
	} {
		l := adm(c.min)
		l.store = st
		err := l.checkAdmins(withMail)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%q: %v", c.min, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%q: %v, want it to say %q", c.min, err, c.wantErr)
		case c.wantErr == "" && l.minCert != c.want:
			t.Errorf("%q: level %v, want %v", c.min, l.minCert, c.want)
		}
	}
	l := localBlock{AdminMinCertification: "L2", store: st}
	if err := l.checkAdmins(withMail); err == nil || !strings.Contains(err.Error(), "without admins") {
		t.Errorf("admin_min_certification without admins: %v", err)
	}
}
